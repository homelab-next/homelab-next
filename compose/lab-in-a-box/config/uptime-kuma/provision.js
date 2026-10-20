// SPDX-License-Identifier: Apache-2.0
//
// Headless provisioning of the lab's Uptime Kuma through its own socket.io API (the one its UI
// uses; Uptime Kuma 1.23 has no REST API for setup, monitors or status pages).  It runs in the
// uptime-kuma image itself, so it uses that image's own socket.io-client, and:
//
//   1. creates the admin user (first run) or logs in;
//   2. reads what exists (the monitorList and statusPageList events Kuma sends after a login)
//      and adds only the missing HTTP monitors: one that answers (KUMA_UP_URL) and one that
//      cannot (KUMA_DOWN_URL);
//   3. waits until each has a heartbeat, so the public API never serves an empty list;
//   4. adds the status page (KUMA_SLUG) if it is missing, then saves it holding both monitors
//      (saving also clears Kuma's API cache);
//   5. writes KUMA_MARKER and stays up: the compose health check is that marker, so
//      `docker compose up --wait` returns only once the status page is there.
//
// Idempotent: on a persisted volume a re-run (a container restart, `up` again) finds both
// monitors and the page, creates nothing, and only saves the page again.  The status hub then
// reads the page with no login at all (/api/status-page/<slug> and
// /api/status-page/heartbeat/<slug>): smoke_checks.py polls it through the real collector.
//
// `provision(kuma, opts)` is the whole procedure against a small client interface, exported so
// tests/compose drives it twice against a fake Kuma; the socket.io client is only built when
// this file is run.
"use strict";

const fs = require("fs");

function must(res, what) {
    if (!res || res.ok === false) {
        throw new Error(`${what}: ${res ? res.msg : "no answer"}`);
    }
    return res;
}

function monitor(name, target) {
    return {
        type: "http",
        name,
        url: target,
        method: "GET",
        interval: 20,
        retryInterval: 20,
        resendInterval: 0,
        maxretries: 0,
        timeout: 10,
        notificationIDList: {},
        ignoreTls: false,
        upsideDown: false,
        maxredirects: 10,
        accepted_statuscodes: [ "200-299" ],
        kafkaProducerBrokers: [],
        kafkaProducerSaslOptions: { mechanism: "None" },
    };
}

// The id of the existing monitor called `name`, or null.  One of that name watching another URL
// is a conflict the operator resolves (provisioning never edits or deletes a monitor).
function existingMonitor(monitors, name, target) {
    const found = Object.values(monitors || {}).filter((m) => m && m.name === name);
    if (found.length > 1) {
        throw new Error(`more than one monitor is called ${name}`);
    }
    if (found.length === 0) {
        return null;
    }
    if (found[0].url !== target) {
        throw new Error(`monitor ${name} exists but watches ${found[0].url}, not ${target}`);
    }
    return Number(found[0].id);
}

function pageExists(pages, slug) {
    return Object.values(pages || {}).some((p) => p && p.slug === slug);
}

// kuma: { call(event, ...args) -> Promise<answer>, lists() -> Promise<{monitors, pages}> (what
// Kuma sent after the login), waitBeats(ids) -> Promise }.
async function provision(kuma, o) {
    if (await kuma.call("needSetup")) {
        must(await kuma.call("setup", o.username, o.password), "setup");
    }
    must(await kuma.call("login", { username: o.username, password: o.password, token: "" }), "login");
    const { monitors, pages } = await kuma.lists();
    const ids = {};
    const created = [];
    for (const [name, target] of [ [ "metrics", o.upURL ], [ "unreachable", o.downURL ] ]) {
        let id = existingMonitor(monitors, name, target);
        if (id === null) {
            id = must(await kuma.call("add", monitor(name, target)), `add ${name}`).monitorID;
            created.push(`monitor ${name}`);
        }
        ids[name] = id;
    }
    await kuma.waitBeats([ ids.metrics, ids.unreachable ]);
    if (!pageExists(pages, o.slug)) {
        must(await kuma.call("addStatusPage", "Lab", o.slug), "addStatusPage");
        created.push(`status page ${o.slug}`);
    }
    const config = {
        slug: o.slug,
        title: "Lab",
        description: "lab-in-a-box status page (provisioned headlessly)",
        theme: "auto",
        showTags: false,
        footerText: "",
        customCSS: "",
        showPoweredBy: false,
        showCertificateExpiry: false,
        googleAnalyticsId: "",
        domainNameList: [],
    };
    const groups = [ { name: "Lab", monitorList: [ { id: ids.metrics }, { id: ids.unreachable } ] } ];
    must(await kuma.call("saveStatusPage", o.slug, config, "/icon.svg", groups), "saveStatusPage");
    return { slug: o.slug, monitors: ids, created };
}

function env(name) {
    const v = process.env[name];
    if (!v) {
        console.error(`provision: ${name} is not set`);
        process.exit(2);
    }
    return v;
}

// The socket.io client of the image (the API the UI uses).
function socketKuma(url, deadline) {
    const { io } = require("socket.io-client");
    const socket = io(url, { transports: [ "websocket" ], reconnection: true });
    const beats = new Set();
    let monitors = null;
    let pages = null;
    socket.on("heartbeat", (beat) => beats.add(Number(beat.monitorID)));
    socket.on("heartbeatList", (id, list) => {
        if (Array.isArray(list) && list.length) {
            beats.add(Number(id));
        }
    });
    socket.on("monitorList", (list) => { monitors = list; });
    socket.on("statusPageList", (list) => { pages = list; });

    async function waitFor(check, what) {
        while (!check()) {
            if (Date.now() > deadline) {
                throw new Error(`timed out waiting for ${what}`);
            }
            await new Promise((r) => setTimeout(r, 500));
        }
    }

    return {
        async call(event, ...args) {
            await waitFor(() => socket.connected, "a connection");
            if (event === "login") {
                monitors = pages = null; // what Kuma sends after this login, not before
            }
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => reject(new Error(`${event}: no answer`)), 30000);
                socket.emit(event, ...args, (res) => {
                    clearTimeout(timer);
                    resolve(res);
                });
            });
        },
        async lists() {
            // Kuma sends the monitor list at once after a login, the status pages ~0.5 s later
            await waitFor(() => monitors !== null && pages !== null, "the monitor and status page lists");
            return { monitors, pages };
        },
        async waitBeats(ids) {
            await waitFor(() => ids.every((id) => beats.has(Number(id))), "the first heartbeats");
        },
    };
}

async function main() {
    const opts = {
        username: env("KUMA_USERNAME"),
        password: env("KUMA_PASSWORD"),
        slug: env("KUMA_SLUG"),
        upURL: env("KUMA_UP_URL"),
        downURL: env("KUMA_DOWN_URL"),
    };
    const url = env("KUMA_URL");
    const marker = env("KUMA_MARKER");
    const deadline = Date.now() + 1000 * Number(process.env.KUMA_TIMEOUT_S || 240);
    const done = await provision(socketKuma(url, deadline), opts);
    fs.writeFileSync(marker, JSON.stringify({ slug: done.slug, monitors: done.monitors }));
    const what = done.created.length ? `created ${done.created.join(", ")}` : "already provisioned";
    console.log(`provision: status page ${done.slug} with monitors ${done.monitors.metrics} and ` +
        `${done.monitors.unreachable} (${what})`);
}

module.exports = { provision, monitor, existingMonitor, pageExists };

if (require.main === module) {
    main().catch((e) => {
        console.error(`provision: ${e.message}`);
        process.exit(1);
    });
    // stay up after provisioning: the health check is the marker file
    setInterval(() => {}, 1 << 30);
}

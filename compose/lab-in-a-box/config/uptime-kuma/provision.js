// SPDX-License-Identifier: Apache-2.0
//
// Headless provisioning of the lab's Uptime Kuma through its own socket.io API (the one its UI
// uses; Uptime Kuma 1.23 has no REST API for setup, monitors or status pages).  It runs in the
// uptime-kuma image itself, so it uses that image's own socket.io-client, and:
//
//   1. creates the admin user (first run) or logs in;
//   2. adds two HTTP monitors: one that answers (KUMA_UP_URL) and one that cannot (KUMA_DOWN_URL);
//   3. waits until each has its first heartbeat, so the public API never serves an empty list;
//   4. publishes a status page (KUMA_SLUG) holding both, which also clears Kuma's API cache;
//   5. writes KUMA_MARKER and stays up: the compose health check is that marker, so
//      `docker compose up --wait` returns only once the status page is there.
//
// The status hub then reads the page with no login at all (/api/status-page/<slug> and
// /api/status-page/heartbeat/<slug>): smoke_checks.py polls it through the real collector.
"use strict";

const fs = require("fs");
const { io } = require("socket.io-client");

const env = (name) => {
    const v = process.env[name];
    if (!v) {
        console.error(`provision: ${name} is not set`);
        process.exit(2);
    }
    return v;
};

const url = env("KUMA_URL");
const username = env("KUMA_USERNAME");
const password = env("KUMA_PASSWORD");
const slug = env("KUMA_SLUG");
const upURL = env("KUMA_UP_URL");
const downURL = env("KUMA_DOWN_URL");
const marker = env("KUMA_MARKER");
const deadline = Date.now() + 1000 * Number(process.env.KUMA_TIMEOUT_S || 240);

const socket = io(url, { transports: [ "websocket" ], reconnection: true });
const beats = new Map();
socket.on("heartbeat", (beat) => beats.set(beat.monitorID, beat.status));

function call(event, ...args) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`${event}: no answer`)), 30000);
        socket.emit(event, ...args, (res) => {
            clearTimeout(timer);
            resolve(res);
        });
    });
}

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

async function waitFor(check, what) {
    while (!check()) {
        if (Date.now() > deadline) {
            throw new Error(`timed out waiting for ${what}`);
        }
        await new Promise((r) => setTimeout(r, 500));
    }
}

async function main() {
    await waitFor(() => socket.connected, "a connection");
    if (await call("needSetup")) {
        must(await call("setup", username, password), "setup");
    }
    must(await call("login", { username, password, token: "" }), "login");
    const up = must(await call("add", monitor("metrics", upURL)), "add metrics").monitorID;
    const down = must(await call("add", monitor("unreachable", downURL)), "add unreachable").monitorID;
    await waitFor(() => beats.has(up) && beats.has(down), "the first heartbeats");
    must(await call("addStatusPage", "Lab", slug), "addStatusPage");
    const config = {
        slug,
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
    const groups = [ { name: "Lab", monitorList: [ { id: up }, { id: down } ] } ];
    must(await call("saveStatusPage", slug, config, "/icon.svg", groups), "saveStatusPage");
    fs.writeFileSync(marker, JSON.stringify({ slug, monitors: { metrics: up, unreachable: down } }));
    console.log(`provision: status page ${slug} published with monitors ${up} and ${down}`);
}

main().catch((e) => {
    console.error(`provision: ${e.message}`);
    process.exit(1);
});
// stay up after provisioning: the health check is the marker file
setInterval(() => {}, 1 << 30);

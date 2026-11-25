---
group: Fixed
---
modules/velociraptor: the generated client configuration dials the published frontend port (same authority, nothing re-initialised); the client role can require the server's own sighting of the client (velociraptor_client_server_host), and the server health can require enrolled, fresh clients (velociraptor_server_health_min_clients).

/*
 * JSVar Hunter test fixture.
 *
 * This file contains intentionally fake values for offline testing.
 */

const apiBase = "/api/v1";
const usersEndpoint = "/api/v1/users";
const accountEndpoint = "/api/account/profile";

const graphqlEndpoint = "/graphql";

const websocketEndpoint = "wss://socket.example.test/ws";

const externalApi = "https://api.example.test/v1/status";

const config = {
    apiUrl: "/api/v1",
    graphql: "/graphql"
};

const fakeApiKey = "TEST_ONLY_FAKE_API_KEY_123456789";
const fakeToken = "TEST_ONLY_FAKE_TOKEN_123456789";

fetch("/api/v1/users");

axios.get("/api/account/profile");

axios.post("/api/v1/login");

const xhr = new XMLHttpRequest();

console.log("JSVar Hunter test fixture");

const sourceMap = "sourceMappingURL=sample.js.map";

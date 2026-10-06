import express from "express";
import request from "supertest";

describe("supertest bound to 127.0.0.1 (test/setup.ts)", () => {
  const cookieApp = () => {
    const app = express();
    app.get("/set", (_req, res) => res.cookie("k", "v").send("ok"));
    app.get("/get", (req, res) => res.send(req.headers.cookie ?? ""));
    return app;
  };

  it("serves request() from a loopback-only server", async () => {
    const app = express();
    app.get("/", (req, res) => res.send(req.socket.localAddress));
    expect((await request(app).get("/")).text).toBe("127.0.0.1");
  });

  it("works with request.agent(), which parses the URL as soon as a request is created", async () => {
    const agent = request.agent(cookieApp());
    await agent.get("/set").expect(200);
    expect((await agent.get("/get")).text).toBe("k=v");
  });
});

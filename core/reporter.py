from .ui import alert_embed


class Reporter:
    def __init__(self, db, feeder, state, cfg):
        self.db, self.feeder, self.state, self.cfg = db, feeder, state, cfg

    async def scraped(self, ip, port, alive, gen=0):
        if not alive:
            self.feeder.push(ip, port, "dead")
            return
        self.state.alive += 1
        self.feeder.push(ip, port, "idrac" if gen else "all")

    async def found(self, ip, port, scheme, verdict, fp):
        self.state.vulns += 1
        self.feeder.push(ip, port, "vuln")
        self.feeder.push_alert(alert_embed(ip, port, scheme, verdict, fp, self.cfg),
                               verdict.confidence)

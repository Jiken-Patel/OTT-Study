'use strict';
// Standalone sink process (used for benchmark runs so its CPU/memory can be sampled separately).
require('dotenv').config();
const { createSink } = require('./oobSink');

const sink = createSink({ deliverKey: process.env.OOB_SINK_DELIVER_KEY, readKey: process.env.OOB_SINK_READ_KEY });
const port = Number(process.env.OOB_SINK_PORT || 4010);
sink.listen(port, '127.0.0.1').then((p) => console.log(`oob sink listening on 127.0.0.1:${p}`))
  .catch((e) => { console.error(e.message); process.exit(1); });

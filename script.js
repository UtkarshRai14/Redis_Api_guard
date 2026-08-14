const axios = require('axios');

const URL = 'http://localhost:3000/api/hello'; // apna API

setInterval(() => {
  for (let i = 0; i < 50; i++) {
    axios.get(URL).catch(() => {});
  }
}, 1000);
import { connect } from "cloudflare:sockets";
const dnsPacket = require("dns-packet");


const HTML = `<!DOCTYPE html>
<html>
<head>
  <title>DNS Lookup</title>
</head>
<body>
  <form id="lookupForm">
    <label for="typeSelector">Record Type:</label>
    <select id="typeSelector">
      <option value="A">A</option>
      <option value="AAAA">AAAA</option>
      <option value="TXT">TXT</option>
      <option value="MX">MX</option>
      <option value="NS">NS</option>
      <option value="SOA">SOA</option>
      <option value="SRV">SRV</option>
      <option value="CAA">CAA</option>
      <option value="CNAME">CNAME</option>
      <option value="DNAME">DNAME</option>
      <option value="DNSKEY">DNSKEY</option>
      <option value="DS">DS</option>
      <option value="HINFO">HINFO</option>
      <option value="NAPTR">NAPTR</option>
      <option value="NSEC">NSEC</option>
      <option value="NSEC3">NSEC3</option>
      <option value="NULL">NULL</option>
      <option value="OPT">OPT</option>
      <option value="PTR">PTR</option>
      <option value="RP">RP</option>
      <option value="SSHFP">SSHFP</option>
      <option value="TLSA">TLSA</option>
      <!-- Add more options as needed -->
    </select>
    
    <br>

    <label for="domain">Domain:</label>
    <input type="text" id="domain" name="domain" value="chaika.me" required>

    <br>
    
    <label for="server">Server:</label>
    <input list="servers" id="server" name="server" value="1.1.1.1" required>
    <datalist id="servers">
      <option value="8.8.8.8">Google - 8.8.8.8</option>
      <option value="9.9.9.9">Quad9 - 9.9.9.9</option>
      <option value="9.9.9.11">Quad9 ECS - 9.9.9.11</option>
      <option value="9.9.9.10">Quad9 NO DNSSEC - 9.9.9.10</option>
      <option value="208.67.222.222">OpenDNS - 208.67.222.222</option>
      <option value="76.76.2.0">ControlD - 76.76.2.0</option>
      <option value="94.140.14.140">Adguard DNS - 94.140.14.14 </option>
      <!-- Add more options as needed -->
    </datalist>

    <br>

    <input type="submit" value="Lookup">
  </form>

  <pre id="output"></pre>

  <script>
    document.getElementById('lookupForm').addEventListener('submit', async function(event) {
      event.preventDefault(); // Prevent the form from submitting in the traditional way

      var type = document.getElementById('typeSelector').value;
      var domain = document.getElementById('domain').value;
      var server = document.getElementById('server').value;

	  if (server === "1.1.1.1" || server === "1.0.0.1" || server === "2606:4700:4700::1111" || server === "2606:4700:4700::1001") {
		document.getElementById('output').innerText = "This uses Cloudflare Workers Connect() which is currently blocked from connecting to CF IPS as per: https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/  \\"Outbound TCP sockets to Cloudflare IP ranges are temporarily blocked, but will be re-enabled shortly.\\"";
		return;
	  }
  

      try {
        const response = await fetch('/api/lookup', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            type: type,
            domain: domain,
            server: server
          })
        });

        const data = await response.text();
        document.getElementById('output').innerText = data;

      } catch (error) {
        console.error('Error:', error);
      }
    });
  </script>
</body>
</html>
`



async function streamToBuffer(readableStream: ReadableStream) {
	const reader = readableStream.getReader();
	const chunks = [];
	let done, value, totalLength = 0, specifiedLength;

	while (true) {
		({ done, value } = await reader.read());
		if (done) {
			break;
		}

		// Push the chunk into chunks array
		const chunk = new Uint8Array(value);
		chunks.push(chunk);

		totalLength += chunk.length;

		// Read the length from the first chunk
		if (chunks.length === 1) {
			const view = new DataView(chunk.buffer);
			specifiedLength = view.getUint16(0, false);  // false for big endian
		}


		// If totalLength >= specifiedLength, break the loop
		if (totalLength >= specifiedLength) {
			break;
		}
	}

	// Create a new Uint8Array with the total length
	const result = new Uint8Array(totalLength);
	let offset = 0;
	for (const chunk of chunks) {
		result.set(chunk, offset);
		offset += chunk.length;
	}

	return result;
}



function getRandomInt(min, max) {
	return Math.floor(Math.random() * (max - min + 1)) + min;
}

export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext
	): Promise<Response> {
		var url = new URL(request.url);
		if (url.pathname === '/') {
			return new Response(HTML, {
				headers: {
					'content-type': 'text/html;charset=UTF-8',
				},
			});
		}
		if (url.pathname !== '/api/lookup') {
			return new Response('Not found', { status: 404 });
		}
		if (request.method !== 'POST') {
			return new Response('Method not allowed', { status: 405 });
		}
		var contentType = request.headers.get('content-type');
		if (contentType !== 'application/json') {
			return new Response('Bad request', { status: 400 });
		}
		var body = await request.json();


		const buf = dnsPacket.streamEncode({
			type: "query",
			id: getRandomInt(1, 65534),
			flags: dnsPacket.RECURSION_DESIRED,
			questions: [
				{
					type: body.type ?? "A",
					name: body.domain,
				},
			],
		});
		const address = {
			hostname: body.server,
			port: 53,
		};

		const socket = connect(address);
		const writableStream = socket.writable.getWriter();
		// Write the buffer to the writable stream
		const uint8Array = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
		await writableStream.write(uint8Array);
		//await writableStream.close();
		var newResponseBuf = await streamToBuffer(socket.readable);

		const buffer = Buffer.from(newResponseBuf, "binary");

		const DnsResponse = dnsPacket.streamDecode(buffer);
		socket.close();
		for (let answer of DnsResponse.answers) {
			if (answer.type == "TXT") {
				answer.data = answer.data.toString();
			}
		}
		return new Response(JSON.stringify(DnsResponse, 0, 2), {
			headers: { "content-type": "application/json" },
		});
	},
};

import http.server
import urllib.request
import re
import base64
from urllib.parse import unquote  # Import unquote to decode URL-encoded strings

class Proxy(http.server.SimpleHTTPRequestHandler):
    MAX_REDIRECTS = 10  # Limit to prevent infinite loops

    def do_GET(self):
        # Show the main page for URL input
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"""
                <html>
                <head><title>Proxy Server</title></head>
                <body>
                    <h1>Proxy Server</h1>
                    <p>Enter a URL to visit:</p>
                    <form action="/proxy" method="get" onsubmit="this.url.value = btoa(this.url.value);">
                        <input type="text" name="url" placeholder="Enter URL" required>
                        <button type="submit">Visit URL</button>
                    </form>
                </body>
                </html>
            """)
            return

        # Handle the proxy request
        if self.path.startswith('/proxy'):
            query = self.path.split('?', 1)[-1]
            params = {}

            # Safely parse key-value pairs from the query string
            for q in query.split('&'):
                if '=' in q:
                    key, value = q.split('=', 1)
                    params[key] = value
                else:
                    params[q] = ''  # If there's no '=' in the string

            # Ensure the URL parameter is present
            if 'url' not in params or not params['url']:
                self.send_error(400, "Bad Request: URL parameter is missing.")
                return

            # URL-decode the Base64 encoded URL
            try:
                # First URL-decode the parameter, then decode it from Base64
                base64_url = unquote(params['url'])  # URL decode
                full_url = self.decode_base64(base64_url)  # Then Base64 decode
            except Exception as e:
                self.send_error(400, f"Bad Request: Failed to decode URL. {str(e)}")
                return

            # Check if the URL starts with http or https
            if not full_url.startswith(('http://', 'https://')):
                self.send_error(400, "Bad Request: URL must start with http:// or https://")
                return

            redirect_count = 0
            while redirect_count < self.MAX_REDIRECTS:
                try:
                    req = urllib.request.Request(full_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req) as response:
                        content = response.read()
                        self.send_response(response.getcode())
                        for header, value in response.getheaders():
                            self.send_header(header, value)
                        self.end_headers()

                        # Only modify HTML content if it's an HTML page
                        if 'text/html' in response.getheader('Content-Type', ''):
                            content = self.modify_html(content)

                        self.wfile.write(content)  # Attempt to write the response
                        return

                except urllib.error.HTTPError as e:
                    self.send_error(e.code, f"HTTP Error: {e.reason}")
                    return
                except urllib.error.URLError as e:
                    self.send_error(500, f"URL Error: {e.reason}")
                    return
                except Exception as e:
                    self.send_error(500, f"Server Error: {str(e)}")
                    return

                redirect_count += 1

            self.send_error(500, "Error: Too many redirects")

    def decode_base64(self, data):
        """Decode a Base64 encoded string."""
        # Clean input and ensure correct padding
        data = data.strip()  # Remove leading and trailing whitespace

        # Append necessary padding to make the length a multiple of 4
        while len(data) % 4 != 0:
            data += '='

        # Validate Base64 input before decoding
        if not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in data):
            raise ValueError("Invalid Base64 input.")

        try:
            decoded_bytes = base64.b64decode(data, validate=True)  # Validate during decoding
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            print(f"Base64 decode error: {str(e)}")  # Log the error
            raise  # Re-raise the exception for handling above

    def modify_html(self, content):
        content_str = content.decode('utf-8')

        # Modify <a> tags to pass URLs directly to the proxy
        content_str = re.sub(r'<a href="(.*?)">(.*?)</a>',
                             lambda m: f'<form action="/proxy" method="get" style="display:inline;">'
                                       f'<input type="hidden" name="url" value="{self.encode_base64(m.group(1))}">'
                                       f'<button type="submit">{m.group(2)}</button></form>', content_str)

        return content_str.encode('utf-8')

    def encode_base64(self, data):
        """Encode a string in Base64."""
        encoded_bytes = base64.b64encode(data.encode('utf-8'))
        return encoded_bytes.decode('utf-8')

def run(server_class=http.server.HTTPServer, handler_class=Proxy, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting proxy server on port {port}...')
    httpd.serve_forever()

if __name__ == "__main__":
    run()

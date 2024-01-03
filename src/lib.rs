use base64::Engine;
use ngx::ffi::{
    nginx_version, ngx_conf_t, ngx_http_add_variable, ngx_http_module_t, ngx_http_request_t,
    ngx_http_variable_t, ngx_int_t, ngx_module_t, ngx_str_t, ngx_uint_t, ngx_variable_value_t,
    NGX_HTTP_MODULE, NGX_RS_MODULE_SIGNATURE,
};
use ngx::{core, core::Status, http, http::HTTPModule};
use ngx::{
    http_variable_get, ngx_http_null_variable, ngx_log_debug_http, ngx_modules, ngx_null_string,
    ngx_string,
};
use std::os::raw::{c_char, c_void};

#[derive(Debug)]
struct NgxBasicAuthUserPassCtx {
    username: ngx_str_t,
    pass: ngx_str_t,
}

impl Default for NgxBasicAuthUserPassCtx {
    fn default() -> NgxBasicAuthUserPassCtx {
        NgxBasicAuthUserPassCtx {
            username: ngx_null_string!(),
            pass: ngx_null_string!(),
        }
    }
}

impl NgxBasicAuthUserPassCtx {
    pub fn save(&mut self, user: &str, pass: &str, pool: &mut core::Pool) -> core::Status {
        let user_len = user.len();
        let user_data = pool.alloc(user_len);
        if user_data.is_null() {
            return core::Status::NGX_ERROR;
        }
        unsafe {
            libc::memcpy(
                user_data,
                user.as_bytes().as_ptr() as *const c_void,
                user_len,
            )
        };
        self.username.len = user_len;
        self.username.data = user_data as *mut u8;

        let pass_str = pass.to_owned();
        let port_data = pool.alloc(pass_str.len());
        if port_data.is_null() {
            return core::Status::NGX_ERROR;
        }
        unsafe {
            libc::memcpy(
                port_data,
                pass_str.as_bytes().as_ptr() as *const c_void,
                pass_str.len(),
            )
        };
        self.pass.len = pass_str.len();
        self.pass.data = port_data as *mut u8;

        core::Status::NGX_OK
    }

    pub unsafe fn bind_username(&self, v: *mut ngx_variable_value_t) {
        if self.username.len == 0 {
            (*v).set_not_found(1);
            return;
        }

        (*v).set_valid(1);
        (*v).set_no_cacheable(0);
        (*v).set_not_found(0);
        (*v).set_len(self.username.len as u32);
        (*v).data = self.username.data;
    }

    pub unsafe fn bind_pass(&self, v: *mut ngx_variable_value_t) {
        if self.pass.len == 0 {
            (*v).set_not_found(1);
            return;
        }

        (*v).set_valid(1);
        (*v).set_no_cacheable(0);
        (*v).set_not_found(0);
        (*v).set_len(self.pass.len as u32);
        (*v).data = self.pass.data;
    }
}

#[no_mangle]
static ngx_basic_auth_decode_module_ctx: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: Some(Module::create_main_conf),
    init_main_conf: Some(Module::init_main_conf),
    create_srv_conf: Some(Module::create_srv_conf),
    merge_srv_conf: Some(Module::merge_srv_conf),
    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

ngx_modules!(ngx_basic_auth_decode_module);

#[no_mangle]
pub static mut ngx_basic_auth_decode_module: ngx_module_t = ngx_module_t {
    ctx_index: ngx_uint_t::max_value(),
    index: ngx_uint_t::max_value(),
    name: std::ptr::null_mut(),
    spare0: 0,
    spare1: 0,
    version: nginx_version as ngx_uint_t,
    signature: NGX_RS_MODULE_SIGNATURE.as_ptr() as *const c_char,
    ctx: &ngx_basic_auth_decode_module_ctx as *const _ as *mut _,
    commands: std::ptr::null_mut(),
    type_: NGX_HTTP_MODULE as ngx_uint_t,

    init_master: None,
    init_module: None,
    init_process: None,
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,

    spare_hook0: 0,
    spare_hook1: 0,
    spare_hook2: 0,
    spare_hook3: 0,
    spare_hook4: 0,
    spare_hook5: 0,
    spare_hook6: 0,
    spare_hook7: 0,
};

#[no_mangle]
static mut ngx_basic_auth_decode_vars: [ngx_http_variable_t; 3] = [
    // ngx_str_t name
    // ngx_http_set_variable_pt set_handler
    // ngx_http_get_variable_pt get_handler
    // uintptr_t data
    // ngx_uint_t flags
    // ngx_uint_t index
    ngx_http_variable_t {
        name: ngx_string!("basic_auth_user"),
        set_handler: None,
        get_handler: Some(ngx_basic_auth_user_variable),
        data: 0,
        flags: 0,
        index: 0,
    },
    ngx_http_variable_t {
        name: ngx_string!("basic_auth_pass"),
        set_handler: None,
        get_handler: Some(ngx_basic_auth_pass_variable),
        data: 0,
        flags: 0,
        index: 0,
    },
    ngx_http_null_variable!(),
];

unsafe fn ngx_get_basic_auth(
    request: &mut http::Request,
) -> Result<(String, String), core::Status> {
    let basic_prefix = "Basic ";
    match request.headers_in_iterator().find_map(|(name, value)| {
        if name.eq_ignore_ascii_case("authorization") && value.len() > basic_prefix.len() {
            value[0..(basic_prefix.len())]
                .eq_ignore_ascii_case(basic_prefix)
                .then(|| value[basic_prefix.len()..].to_owned())
        } else {
            None
        }
    }) {
        Some(token) => {
            let decoded = base64::prelude::BASE64_STANDARD
                .decode(token)
                .map_err(|e| {
                    ngx_log_debug_http!(
                        request,
                        "basic_auth_decode: failed to decode token: {:?}",
                        e
                    );
                    core::Status::NGX_DECLINED
                })?;
            let decoded = String::from_utf8(decoded).map_err(|e| {
                ngx_log_debug_http!(
                    request,
                    "basic_auth_decode: failed to convert to string: {:?}",
                    e
                );
                core::Status::NGX_DECLINED
            })?;
            decoded
                .split_once(':')
                .map(|(user, pass)| (user.to_owned(), pass.to_owned()))
                .ok_or_else(|| {
                    ngx_log_debug_http!(
                        request,
                        "basic_auth_decode: invalid auth token(missing :)"
                    );
                    core::Status::NGX_DECLINED
                })
        }
        None => {
            ngx_log_debug_http!(request, "missing auth header");
            Err(core::Status::NGX_DECLINED)
        }
    }
}

http_variable_get!(
    ngx_basic_auth_user_variable,
    |request: &mut http::Request, v: *mut ngx_variable_value_t, _: usize| {
        let ctx = request.get_module_ctx::<NgxBasicAuthUserPassCtx>(&ngx_basic_auth_decode_module);
        if let Some(obj) = ctx {
            ngx_log_debug_http!(
                request,
                "basic_auth_decode: found context and binding variable",
            );
            obj.bind_username(v);
            return core::Status::NGX_OK;
        }
        // lazy initialization:
        //   get original dest information
        //   create context
        //   set context
        // bind address
        ngx_log_debug_http!(
            request,
            "basic_auth_decode: context not found, getting username"
        );
        let r = ngx_get_basic_auth(request);
        match r {
            Err(e) => {
                return e;
            }
            Ok((username, pass)) => {
                // create context,
                // set context
                let new_ctx = request
                    .pool()
                    .allocate::<NgxBasicAuthUserPassCtx>(Default::default());

                if new_ctx.is_null() {
                    return core::Status::NGX_ERROR;
                }

                ngx_log_debug_http!(
                    request,
                    "basic_auth_decode: saving user - {:?}, pass - {}",
                    masked(&username),
                    masked(&pass),
                );
                (*new_ctx).save(&username, &pass, &mut request.pool());
                (*new_ctx).bind_username(v);
                request.set_module_ctx(new_ctx as *mut c_void, &ngx_basic_auth_decode_module);
            }
        }
        core::Status::NGX_OK
    }
);

http_variable_get!(
    ngx_basic_auth_pass_variable,
    |request: &mut http::Request, v: *mut ngx_variable_value_t, _: usize| {
        let ctx = request.get_module_ctx::<NgxBasicAuthUserPassCtx>(&ngx_basic_auth_decode_module);
        if let Some(obj) = ctx {
            ngx_log_debug_http!(
                request,
                "basic_auth_decode: found context and binding variable",
            );
            obj.bind_pass(v);
            return core::Status::NGX_OK;
        }
        // lazy initialization:
        //   get original dest information
        //   create context
        //   set context
        // bind port
        ngx_log_debug_http!(
            request,
            "basic_auth_decode: context not found, getting pass"
        );
        let r = ngx_get_basic_auth(request);
        match r {
            Err(e) => {
                return e;
            }
            Ok((username, pass)) => {
                // create context,
                // set context
                let new_ctx = request
                    .pool()
                    .allocate::<NgxBasicAuthUserPassCtx>(Default::default());

                if new_ctx.is_null() {
                    return core::Status::NGX_ERROR;
                }

                ngx_log_debug_http!(
                    request,
                    "basic_auth_decode: saving user - {}, pass - {}",
                    masked(&username),
                    masked(&pass),
                );
                (*new_ctx).save(&username, &pass, &mut request.pool());
                (*new_ctx).bind_pass(v);
                request.set_module_ctx(new_ctx as *mut c_void, &ngx_basic_auth_decode_module);
            }
        }
        core::Status::NGX_OK
    }
);

struct Module;

impl HTTPModule for Module {
    type MainConf = ();
    type SrvConf = ();
    type LocConf = ();

    unsafe extern "C" fn preconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        for mut v in ngx_basic_auth_decode_vars {
            if v.name.len == 0 {
                break;
            }
            let var = ngx_http_add_variable(cf, &mut v.name, v.flags);
            if var.is_null() {
                return core::Status::NGX_ERROR.into();
            }
            (*var).get_handler = v.get_handler;
            (*var).data = v.data;
        }
        core::Status::NGX_OK.into()
    }
}

fn masked(s: &String) -> String {
    format!(
        "{}******{}",
        s.chars().next().unwrap_or(' '),
        s.chars().last().unwrap_or(' ')
    )
}

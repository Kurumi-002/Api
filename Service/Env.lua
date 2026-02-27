local RunService = cloneref(game:GetService("RunService"))

local code = {}
local PublicRendering = {}

code.cleaning = function(env)
    if not env then return end

    local ok, err = pcall(function()
        local t = typeof(env)
        if t == "thread" then
            task.cancel(env)
        elseif t == "RBXScriptConnection" then
            env:Disconnect()
        elseif t == "Instance" then
            env:Destroy()
        elseif t == "table" then
            if type(env.Destroy) == "function" then
                env:Destroy()
            elseif type(env.Disconnect) == "function" then
                env:Disconnect()
            end
        end
    end)

    if not ok then
        warn("[Env] cleanup error:", err)
    end
end

code.secure_call = function(Function, fromscript, ...)
    if not Function or not fromscript then
        warn("[Env] secure_call: missing args")
        return
    end

    local old_traceback = getrenv().debug.traceback
    local old_getexecutorname = getgenv().getexecutorname
    local scriptName = tostring(fromscript:GetFullName())

    setreadonly(getrenv().debug, false)
    getgenv().getexecutorname = nil
    getrenv().debug.traceback = function()
        return scriptName
    end

    local results = { pcall(Function, ...) }

    getrenv().debug.traceback = old_traceback
    getgenv().getexecutorname = old_getexecutorname
    setreadonly(getrenv().debug, true)

    if not results[1] then
        warn("[Env] secure_call error:", results[2])
        return nil
    end

    return select(2, unpack(results))
end

code.sleep = function(time)
    return task.wait(time)
end

code.secure_require = function(Module)
    if not Module or not Module:IsA("ModuleScript") then return end

    local env = require(Module)
    local ok, mt = pcall(getrawmetatable, env)

    if not ok or not mt then return env end

    pcall(function()
        local wasReadonly = isreadonly(mt)
        if wasReadonly then setreadonly(mt, false) end
        if mt.__tostring then mt.__tostring = nil end
        if wasReadonly then setreadonly(mt, true) end
    end)

    return env
end

code.rendering = function(Function, Mode)
    if type(Function) ~= "function" then
        warn("[Env] rendering: arg1 not function")
        return
    end

    local InProgress = false
    local rendering = RunService.Heartbeat:Connect(function()
        if Mode then
            Function()
            return
        end

        if InProgress then return end
        InProgress = true
        local ok, err = pcall(Function)
        InProgress = false
        if not ok then
            warn("[Env] rendering error:", err)
        end
    end)

    return rendering
end

code.public_rendering = function(Function, mode)
    if type(Function) ~= "function" then
        warn("[Env] public_rendering: arg1 not function")
        return
    end

    local newTask = {
        Thread = Function,
        Mode = mode,
        Running = true,
    }

    table.insert(PublicRendering, newTask)

    if not code.main_rendering then
        code.main_rendering = RunService.Heartbeat:Connect(function()
            for i = #PublicRendering, 1, -1 do
                local asset = PublicRendering[i]
                if not asset or not asset.Running then
                    table.remove(PublicRendering, i)
                    continue
                end

                local ok, err = pcall(asset.Thread)
                if not ok then
                    warn("[Env] public_rendering task error:", err)
                    asset.Running = false
                end
            end
        end)
    end

    return newTask
end

code.public_rendering_clear = function()
    if code.main_rendering then
        code.main_rendering:Disconnect()
        code.main_rendering = nil
    end
    table.clear(PublicRendering)
    return true
end

code.secure_thread = function(func, ...)
    if type(func) ~= "function" then return false, "arg1 not function" end
    return pcall(func, ...)
end

code.protect_call = function(...)
    return pcall(...)
end

return code

'use strict';

// Read-only crash/termination tracer for authorized iOS testing. It records
// native termination calls and fatal exceptions, but never changes return
// values, signals, trust decisions, or application data.
(function () {
  function globalExport(name) {
    try { return Module.getGlobalExportByName(name); } catch (_) { return null; }
  }
  function describeAddress(address) {
    try {
      const module = Process.findModuleByAddress(address);
      if (!module) return { address: address.toString() };
      return {
        address: address.toString(),
        module: module.name,
        modulePath: module.path,
        moduleOffset: address.sub(module.base).toString()
      };
    } catch (error) {
      return { address: String(address), error: String(error) };
    }
  }
  function backtrace(context) {
    try {
      return Thread.backtrace(context, Backtracer.FUZZY).slice(0, 40).map(describeAddress);
    } catch (error) {
      return [{ error: String(error) }];
    }
  }
  function emit(type, payload) {
    console.log(JSON.stringify(Object.assign({ type: type, pid: Process.id }, payload || {})));
  }

  const hooked = [];
  ['exit', '_exit', 'abort', '__abort_with_payload', 'terminate_with_reason',
   'pthread_kill', '__pthread_kill', 'kill', 'raise', 'objc_exception_throw'].forEach(function (name) {
    const target = globalExport(name);
    if (!target) return;
    Interceptor.attach(target, {
      onEnter(args) {
        let argumentsSummary = [];
        try {
          if (name === 'kill') argumentsSummary = [args[0].toInt32(), args[1].toInt32()];
          else if (name === 'pthread_kill' || name === '__pthread_kill') argumentsSummary = [args[1].toInt32()];
          else if (name === 'raise' || name === 'exit' || name === '_exit') argumentsSummary = [args[0].toInt32()];
        } catch (_) {}
        emit('ME_IOS_TERMINATION_CALL', {
          symbol: name,
          caller: describeAddress(this.returnAddress),
          arguments: argumentsSummary,
          backtrace: backtrace(this.context)
        });
      }
    });
    hooked.push(name);
  });

  let exceptionHandlerInstalled = false;
  try {
    exceptionHandlerInstalled = Process.setExceptionHandler(function (details) {
      const context = details.context || {};
      emit('ME_IOS_FATAL_EXCEPTION', {
        exceptionType: details.type,
        address: details.address ? describeAddress(details.address) : null,
        memory: details.memory || null,
        pc: context.pc ? describeAddress(context.pc) : null,
        lr: context.lr ? describeAddress(context.lr) : null,
        backtrace: backtrace(context)
      });
      return false;
    });
  } catch (error) {
    emit('ME_IOS_EXCEPTION_HANDLER_ERROR', { error: String(error) });
  }

  emit('ME_IOS_TERMINATION_TRACE_READY', {
    mainModule: describeAddress(Process.mainModule.base),
    hooked: hooked,
    exceptionHandlerInstalled: exceptionHandlerInstalled
  });
})();

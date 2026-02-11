use std::collections::HashMap;

/// Per-GPU device information for the header bars.
#[derive(Debug, Clone, Default)]
pub struct GpuDeviceInfo {
    pub index: u32,
    pub name: String,
    pub utilization_pct: u32,
    pub memory_used: u64,
    pub memory_total: u64,
}

/// Per-process GPU usage, summed across all GPUs.
#[derive(Debug, Clone, Default)]
pub struct ProcessGpuUsage {
    pub gpu_percent: f64,
    pub gpu_mem_bytes: u64,
}

#[cfg(feature = "gpu")]
pub struct GpuCollector {
    nvml: nvml_wrapper::Nvml,
    device_count: u32,
    last_sample_timestamp: u64,
}

#[cfg(feature = "gpu")]
impl GpuCollector {
    /// Try to initialize NVML. Returns None if no NVIDIA driver or GPUs are present.
    /// Tries the default library path first, then NixOS-specific paths.
    pub fn try_new() -> Option<Self> {
        let nvml = nvml_wrapper::Nvml::init()
            .or_else(|_| {
                // NixOS: libnvidia-ml.so lives under /run/opengl-driver/lib/
                nvml_wrapper::Nvml::builder()
                    .lib_path(std::ffi::OsStr::new("/run/opengl-driver/lib/libnvidia-ml.so"))
                    .init()
            });
        let nvml = match nvml {
            Ok(n) => n,
            Err(e) => {
                log::debug!("NVML init failed: {e}");
                return None;
            }
        };
        let device_count = match nvml.device_count() {
            Ok(c) if c > 0 => c,
            Ok(_) => {
                log::debug!("NVML: no GPUs found");
                return None;
            }
            Err(e) => {
                log::debug!("NVML device_count failed: {e}");
                return None;
            }
        };
        log::info!("NVML initialized: {device_count} GPU(s)");
        Some(Self {
            nvml,
            device_count,
            last_sample_timestamp: 0,
        })
    }

    /// Collect per-device stats and per-process GPU usage.
    pub fn collect(&mut self) -> (Vec<GpuDeviceInfo>, HashMap<u32, ProcessGpuUsage>) {
        let mut devices = Vec::with_capacity(self.device_count as usize);
        let mut proc_gpu: HashMap<u32, ProcessGpuUsage> = HashMap::new();

        for idx in 0..self.device_count {
            let device = match self.nvml.device_by_index(idx) {
                Ok(d) => d,
                Err(e) => {
                    log::debug!("NVML device_by_index({idx}) failed: {e}");
                    continue;
                }
            };

            // Device-level stats
            let name = device.name().unwrap_or_else(|_| format!("GPU {idx}"));
            let utilization = device.utilization_rates().map(|u| u.gpu).unwrap_or(0);
            let mem_info = device.memory_info();
            let (mem_used, mem_total) = match mem_info {
                Ok(m) => (m.used, m.total),
                Err(_) => (0, 0),
            };

            devices.push(GpuDeviceInfo {
                index: idx,
                name,
                utilization_pct: utilization,
                memory_used: mem_used,
                memory_total: mem_total,
            });

            // Per-process VRAM: merge compute + graphics, dedup by PID (take max)
            let mut per_device_mem: HashMap<u32, u64> = HashMap::new();
            if let Ok(procs) = device.running_compute_processes() {
                for p in procs {
                    let pid = p.pid;
                    let mem = match p.used_gpu_memory {
                        nvml_wrapper::enums::device::UsedGpuMemory::Used(b) => b,
                        _ => 0,
                    };
                    per_device_mem
                        .entry(pid)
                        .and_modify(|e| *e = (*e).max(mem))
                        .or_insert(mem);
                }
            }
            if let Ok(procs) = device.running_graphics_processes() {
                for p in procs {
                    let pid = p.pid;
                    let mem = match p.used_gpu_memory {
                        nvml_wrapper::enums::device::UsedGpuMemory::Used(b) => b,
                        _ => 0,
                    };
                    per_device_mem
                        .entry(pid)
                        .and_modify(|e| *e = (*e).max(mem))
                        .or_insert(mem);
                }
            }

            // Sum VRAM across devices into proc_gpu
            for (pid, mem) in &per_device_mem {
                proc_gpu
                    .entry(*pid)
                    .and_modify(|e| e.gpu_mem_bytes += mem)
                    .or_insert(ProcessGpuUsage {
                        gpu_percent: 0.0,
                        gpu_mem_bytes: *mem,
                    });
            }

            // Per-process GPU% via process_utilization_stats
            if let Ok(stats) = device.process_utilization_stats(self.last_sample_timestamp) {
                for s in stats {
                    proc_gpu
                        .entry(s.pid)
                        .and_modify(|e| e.gpu_percent += s.sm_util as f64)
                        .or_insert(ProcessGpuUsage {
                            gpu_percent: s.sm_util as f64,
                            gpu_mem_bytes: 0,
                        });
                }
            }
        }

        // Update timestamp for next sample
        self.last_sample_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        (devices, proc_gpu)
    }
}

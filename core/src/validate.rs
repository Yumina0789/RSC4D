

use crate::codec::VERSION_SIZE;

pub const PID_BUFFER_SIZE: usize = 64;

pub const MAX_PID_SIZE: u32 = (PID_BUFFER_SIZE as u32) << 1;

pub const PID_SIZE_FIELD: usize = 4;

pub const PID_OFFSET: usize = VERSION_SIZE + PID_SIZE_FIELD;

pub fn check_pid_length(response_base: &[u8]) -> bool {

    let Some(field) = response_base.get(VERSION_SIZE..PID_OFFSET) else {
        return false;
    };
    let pid_size = u32::from_le_bytes([field[0], field[1], field[2], field[3]]);

    if pid_size < 2 || pid_size % 2 != 0 || pid_size > MAX_PID_SIZE {
        return false;
    }

    let wchars = pid_size as usize / 2;
    let Some(pid) = response_base.get(PID_OFFSET..PID_OFFSET + pid_size as usize) else {
        return false;
    };

    if !wchar_is_nul(pid, wchars - 1) {
        return false;
    }

    (0..wchars - 1).all(|i| !wchar_is_nul(pid, i))
}

fn wchar_is_nul(pid: &[u8], index: usize) -> bool {
    u16::from_le_bytes([pid[index * 2], pid[index * 2 + 1]]) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSION: [u8; 4] = [0x00, 0x00, 0x04, 0x00];

    fn prefix(pid_size: u32, epid: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(PID_OFFSET + epid.len());
        out.extend_from_slice(&VERSION);
        out.extend_from_slice(&pid_size.to_le_bytes());
        out.extend_from_slice(epid);
        out
    }

    fn ucs2_z(pid: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity((pid.encode_utf16().count() + 1) * 2);
        for unit in pid.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&[0, 0]);
        out
    }

    fn pid_size_of(pid: &str) -> u32 {
        ((pid.encode_utf16().count() + 1) * 2) as u32
    }

    #[test]
    fn pid_size_zero_is_rejected() {

        assert!(!check_pid_length(&prefix(0, &[0, 0])));
    }

    #[test]
    fn odd_pid_size_is_rejected() {
        assert!(!check_pid_length(&prefix(1, &[0])));
        assert!(!check_pid_length(&prefix(127, &[0x41; 127])));
    }

    #[test]
    fn minimal_pid_size_two_is_accepted() {

        assert!(check_pid_length(&prefix(2, &[0, 0])));
    }

    #[test]
    fn real_epid_is_accepted() {
        let epid = "03612-00206-556-123727-03-1033-17763.0000-2972018";
        let bytes = ucs2_z(epid);
        assert_eq!(bytes.len(), pid_size_of(epid) as usize);
        assert!(check_pid_length(&prefix(pid_size_of(epid), &bytes)));
    }

    #[test]
    fn pid_size_at_upper_bound_is_accepted() {

        let mut bytes = [0x41, 0x00].repeat(PID_BUFFER_SIZE - 1);
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(bytes.len(), MAX_PID_SIZE as usize);
        assert!(check_pid_length(&prefix(MAX_PID_SIZE, &bytes)));
    }

    #[test]
    fn pid_size_above_upper_bound_is_rejected() {

        let mut bytes = [0x41, 0x00].repeat(64);
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(bytes.len(), 130);
        assert!(!check_pid_length(&prefix(130, &bytes)));
    }

    #[test]
    fn huge_pid_size_is_rejected_without_panic() {

        assert!(!check_pid_length(&prefix(u32::MAX, &[0u8; 16])));
    }

    #[test]
    fn missing_terminating_nul_is_rejected() {

        assert!(!check_pid_length(&prefix(6, &[0x41, 0, 0x42, 0, 0x43, 0])));
    }

    #[test]
    fn embedded_nul_is_rejected() {

        assert!(!check_pid_length(&prefix(6, &[0x41, 0, 0, 0, 0, 0])));
        assert!(!check_pid_length(&prefix(4, &[0, 0, 0, 0])));
    }

    #[test]
    fn truncated_prefix_is_rejected() {

        assert!(!check_pid_length(&[]));
        assert!(!check_pid_length(&VERSION));
        assert!(!check_pid_length(&prefix(128, &[])));

        assert!(!check_pid_length(&prefix(8, &[0x41, 0, 0x42, 0])));

        let mut short = [0x41, 0x00].repeat(63);
        short.truncate(60);
        assert!(!check_pid_length(&prefix(MAX_PID_SIZE, &short)));
    }
}

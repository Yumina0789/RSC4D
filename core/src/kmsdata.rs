

#[derive(Debug, Clone, Copy)]
pub struct Csvlk {

    pub epid: &'static str,

    pub group_id: u32,

    pub min_key_id: u32,
    pub max_key_id: u32,

    pub min_active_clients: u8,

    pub release_date: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct Product {

    pub name: &'static str,

    pub kms_id: [u8; 16],

    pub app_id: [u8; 16],

    pub csvlk_index: usize,

    pub protocol_version: u8,

    pub n_count_policy: u8,
    pub is_retail: bool,
    pub is_preview: bool,
}

include!("kmsdata_gen.rs");

pub fn find_product_by_kms_id(kms_id: &[u8; 16]) -> Option<(usize, &'static Product)> {
    PRODUCTS
        .iter()
        .enumerate()
        .rev()
        .find(|(_, p)| &p.kms_id == kms_id)
}

pub fn csvlk_for(product_index: Option<usize>) -> &'static Csvlk {
    let idx = product_index
        .map(|i| PRODUCTS[i].csvlk_index)
        .unwrap_or(0)
        .min(CSVLK.len() - 1);
    &CSVLK[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tables_are_consistent() {
        assert!(!CSVLK.is_empty(), "CSVLK table is empty");
        assert!(!PRODUCTS.is_empty(), "PRODUCTS table is empty");

        for p in PRODUCTS {
            assert!(p.csvlk_index < CSVLK.len(), "{}: csvlk_index out of bounds", p.name);
            assert!(
                (4..=6).contains(&p.protocol_version),
                "{}: protocol version {} not in 4..=6",
                p.name,
                p.protocol_version
            );
        }
        for c in CSVLK {
            assert!(!c.epid.is_empty(), "ePID is empty");
        }
    }

    #[test]
    fn table_covers_windows_and_office() {
        assert!(
            PRODUCTS.iter().any(|p| p.name.contains("Windows")),
            "no Windows product"
        );
        assert!(
            PRODUCTS.iter().any(|p| p.name.contains("Office")),
            "no Office product"
        );
    }

    #[test]
    fn epid_templates_are_well_formed() {
        for c in CSVLK {
            let parts: Vec<&str> = c.epid.split('-').collect();
            assert!(parts.len() >= 5, "{:?}: too few segments", c.epid);
            assert!(
                parts[0].len() == 5 && parts[0].chars().all(|ch| ch.is_ascii_digit()),
                "{:?}: platform segment must be 5 digits",
                c.epid
            );
            assert_eq!(parts[4], "03", "{:?}: version segment must be 03", c.epid);
            assert_eq!(
                parts[1].parse::<u32>().unwrap(),
                c.group_id,
                "{:?}: group segment does not match GroupId",
                c.epid
            );
        }
    }
}

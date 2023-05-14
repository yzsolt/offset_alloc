mod small_float;

use small_float::SmallFloat;

// 16 bit offsets mode will halve the metadata storage cost
// But it only supports up to 65536 maximum allocation count
#[cfg(USE_16_BIT_NODE_INDICES)]
type NodeIndex = u16;

#[cfg(not(USE_16_BIT_NODE_INDICES))]
type NodeIndex = u32;

const NUM_TOP_BINS: u32 = 32;
const BINS_PER_LEAF: u32 = 8;
const TOP_BINS_INDEX_SHIFT: u32 = 3;
const LEAF_BINS_INDEX_MASK: u32 = 0x7;
const NUM_LEAF_BINS: u32 = NUM_TOP_BINS * BINS_PER_LEAF;

#[derive(Clone, Copy)]
pub struct Allocation {
    /// Offset in bytes
    pub offset: u32,

    metadata: NodeIndex,
}

const INVALID_INDEX: u32 = 0xFFFFFFFF;

pub struct StorageReport {
    pub total_free_space: u32,
    pub largest_free_region: u32,
}

#[derive(Clone, Copy, Default)]
pub struct Region {
    pub size: u32,
    pub count: u32,
}

pub struct StorageReportFull {
    pub free_regions: [Region; NUM_LEAF_BINS as usize],
}

#[derive(Clone)]
struct Node {
    data_offset: u32,
    data_size: u32,
    bin_list_prev: NodeIndex,
    bin_list_next: NodeIndex,
    neighbor_prev: NodeIndex,
    neighbor_next: NodeIndex,
    used: bool, // TODO: Merge as bit flag
}

impl Node {
    const UNUSED: NodeIndex = INVALID_INDEX;
}

impl Default for Node {
    fn default() -> Self {
        Self {
            data_offset: 0,
            data_size: 0,
            bin_list_prev: Self::UNUSED,
            bin_list_next: Self::UNUSED,
            neighbor_prev: Self::UNUSED,
            neighbor_next: Self::UNUSED,
            used: false,
        }
    }
}

fn find_lowest_set_bit_after(bit_mask: u32, start_bit_index: u32) -> u32 {
    let mask_before_start_index = (1 << start_bit_index) - 1;
    let mask_after_start_index = !mask_before_start_index;
    let bits_after = bit_mask & mask_after_start_index;

    if bits_after == 0 {
        INVALID_INDEX
    } else {
        bits_after.trailing_zeros()
    }
}

pub struct Allocator {
    size: u32,
    max_allocs: u32,
    free_storage: u32,
    used_bins_top: u32,
    used_bins: [u8; NUM_TOP_BINS as usize],
    bin_indices: [NodeIndex; NUM_LEAF_BINS as usize],
    nodes: Vec<Node>,
    free_nodes: Vec<NodeIndex>,
    free_offset: u32,
}

impl Allocator {
    pub const DEFAULT_MAX_ALLOCS: u32 = 128 * 1024;

    pub fn new(size: u32, max_allocs: u32) -> Self {
        #[cfg(USE_16_BIT_NODE_INDICES)]
        assert!(max_allocs <= 65536);

        let mut allocator = Self {
            size,
            max_allocs,
            free_storage: 0,
            used_bins_top: 0,
            used_bins: [0; NUM_TOP_BINS as usize],
            bin_indices: [Node::UNUSED; NUM_LEAF_BINS as usize],
            nodes: vec![Node::default(); max_allocs as usize],
            free_nodes: vec![NodeIndex::default(); max_allocs as usize],
            free_offset: max_allocs - 1,
        };

        // Freelist is a stack. Nodes in inverse order so that [0] pops first.
        for (i, free_node) in allocator.free_nodes.iter_mut().enumerate() {
            *free_node = allocator.max_allocs - i as u32 - 1;
        }

        // Start state: Whole storage as one big node
        // Algorithm will split remainders and push them back as smaller nodes
        allocator.insert_node_into_bin(allocator.size, 0);

        allocator
    }

    pub fn allocate(&mut self, size: u32) -> Option<Allocation> {
        // Out of allocations?
        if self.free_offset == 0 {
            return None;
        }

        // Round up to bin index to ensure that alloc >= bin
        // Gives us min bin index that fits the size
        let min_bin_index: u32 = SmallFloat::from_u32_round_up(size).raw_value();

        let min_top_bin_index = min_bin_index >> TOP_BINS_INDEX_SHIFT;
        let min_leaf_bin_index = min_bin_index & LEAF_BINS_INDEX_MASK;

        let mut top_bin_index = min_top_bin_index;
        let mut leaf_bin_index = INVALID_INDEX;

        // If top bin exists, scan its leaf bin. This can fail (INVALID_INDEX).
        if (self.used_bins_top & (1 << top_bin_index)) != 0 {
            leaf_bin_index = find_lowest_set_bit_after(
                self.used_bins[top_bin_index as usize] as u32,
                min_leaf_bin_index,
            );
        }

        // If we didn't find space in top bin, we search top bin from +1
        if leaf_bin_index == INVALID_INDEX {
            top_bin_index = find_lowest_set_bit_after(self.used_bins_top, min_top_bin_index + 1);

            // Out of space?
            if top_bin_index == INVALID_INDEX {
                return None;
            }

            // All leaf bins here fit the alloc, since the top bin was rounded up. Start leaf search from bit 0.
            // NOTE: This search can't fail since at least one leaf bit was set because the top bit was set.
            leaf_bin_index = (self.used_bins[top_bin_index as usize] as u32).trailing_zeros();
        }

        let bin_index = (top_bin_index << TOP_BINS_INDEX_SHIFT) | leaf_bin_index;

        // Pop the top node of the bin. Bin top = node.next.
        let node_index = self.bin_indices[bin_index as usize];
        let node = self.nodes[node_index as usize].clone();
        let node_total_size = node.data_size;

        {
            let node_mut = &mut self.nodes[node_index as usize];
            node_mut.data_size = size;
            node_mut.used = true;
        }
        let node = self.nodes[node_index as usize].clone();

        self.bin_indices[bin_index as usize] = node.bin_list_next;
        if node.bin_list_next != Node::UNUSED {
            self.nodes[node.bin_list_next as usize].bin_list_prev = Node::UNUSED;
        }
        self.free_storage -= node_total_size;

        // Bin empty?
        if self.bin_indices[bin_index as usize] == Node::UNUSED {
            // Remove a leaf bin mask bit
            self.used_bins[top_bin_index as usize] &= !(1 << leaf_bin_index);

            // All leaf bins empty?
            if self.used_bins[top_bin_index as usize] == 0 {
                // Remove a top bin mask bit
                self.used_bins_top &= !(1 << top_bin_index);
            }
        }

        // Push back remainder N elements to a lower bin
        let remainder_size = node_total_size - size;
        if remainder_size > 0 {
            let new_node_index = self.insert_node_into_bin(remainder_size, node.data_offset + size);

            // Link nodes next to each other so that we can merge them later if both are free
            // And update the old next neighbor to point to the new node (in middle)
            if node.neighbor_next != Node::UNUSED {
                self.nodes[node.neighbor_next as usize].neighbor_prev = new_node_index;
            }

            {
                let new_node = &mut self.nodes[new_node_index as usize];
                new_node.neighbor_prev = node_index;
                new_node.neighbor_next = node.neighbor_next;
            }

            let node_mut = &mut self.nodes[node_index as usize];
            node_mut.neighbor_next = new_node_index;
        }

        assert_ne!(node.data_offset, INVALID_INDEX);
        assert_ne!(node_index, INVALID_INDEX);

        Some(Allocation {
            offset: node.data_offset,
            metadata: node_index,
        })
    }

    pub fn free(&mut self, allocation: Allocation) {
        if self.nodes.is_empty() {
            return;
        }

        let node_index = allocation.metadata;
        let node = self.nodes[node_index as usize].clone();

        // Double delete check
        assert!(node.used == true);

        // Merge with neighbors...
        let mut offset = node.data_offset;
        let mut size = node.data_size;

        if (node.neighbor_prev != Node::UNUSED)
            && (self.nodes[node.neighbor_prev as usize].used == false)
        {
            // Previous (contiguous) free node: Change offset to previous node offset. Sum sizes
            {
                let prev_node = &self.nodes[node.neighbor_prev as usize];
                offset = prev_node.data_offset;
                size += prev_node.data_size;
            }

            // Remove node from the bin linked list and put it in the freelist
            self.remove_node_from_bin(node.neighbor_prev);

            {
                let prev_node = self.nodes[node.neighbor_prev as usize].clone();
                assert!(prev_node.neighbor_next == node_index);

                let node_mut = &mut self.nodes[node_index as usize];
                node_mut.neighbor_prev = prev_node.neighbor_prev;
            }
        }

        if (node.neighbor_next != Node::UNUSED)
            && (self.nodes[node.neighbor_next as usize].used == false)
        {
            // Next (contiguous) free node: Offset remains the same. Sum sizes.
            {
                let next_node = &self.nodes[node.neighbor_next as usize];
                size += next_node.data_size;
            }

            // Remove node from the bin linked list and put it in the freelist
            self.remove_node_from_bin(node.neighbor_next);

            {
                let next_node = self.nodes[node.neighbor_next as usize].clone();
                assert!(next_node.neighbor_prev == node_index);

                let node_mut = &mut self.nodes[node_index as usize];
                node_mut.neighbor_next = next_node.neighbor_next;
            }
        }

        let node = self.nodes[node_index as usize].clone(); // Reclone as it may have changed in the meantime
        let neighbor_next = node.neighbor_next;
        let neighbor_prev = node.neighbor_prev;

        // Insert the removed node to freelist
        self.free_offset += 1;
        self.free_nodes[self.free_offset as usize] = node_index;

        // Insert the (combined) free node to bin
        let combined_node_index = self.insert_node_into_bin(size, offset);

        // Connect neighbors with the new combined node
        if neighbor_next != Node::UNUSED {
            self.nodes[combined_node_index as usize].neighbor_next = neighbor_next;
            self.nodes[neighbor_next as usize].neighbor_prev = combined_node_index;
        }

        if neighbor_prev != Node::UNUSED {
            self.nodes[combined_node_index as usize].neighbor_prev = neighbor_prev;
            self.nodes[neighbor_prev as usize].neighbor_next = combined_node_index;
        }
    }

    pub fn allocation_size(&self, allocation: &Allocation) -> u32 {
        if self.nodes.is_empty() {
            0
        } else {
            self.nodes[allocation.metadata as usize].data_size
        }
    }

    pub fn storage_report(&self) -> StorageReport {
        let mut largest_free_region = 0;
        let mut total_free_space = 0;

        // Out of allocations? -> Zero free space
        if self.free_offset > 0 {
            total_free_space = self.free_storage;
            if self.used_bins_top != 0 {
                let top_bin_index = 31 - self.used_bins_top.leading_zeros();
                let leaf_bin_index =
                    31 - (self.used_bins[top_bin_index as usize] as u32).leading_zeros();
                largest_free_region = SmallFloat::from_u32_raw(
                    (top_bin_index << TOP_BINS_INDEX_SHIFT) | leaf_bin_index,
                )
                .into();
                assert!(total_free_space >= largest_free_region);
            }
        }

        StorageReport {
            total_free_space,
            largest_free_region,
        }
    }

    pub fn storage_report_full(&self) -> StorageReportFull {
        let mut report = StorageReportFull {
            free_regions: [Region::default(); NUM_LEAF_BINS as usize],
        };

        for i in 0..NUM_LEAF_BINS {
            let mut count = 0;
            let mut node_index = self.bin_indices[i as usize];
            while node_index != Node::UNUSED {
                node_index = self.nodes[node_index as usize].bin_list_next;
                count += 1;
            }
            report.free_regions[i as usize] = Region {
                size: SmallFloat::from_u32_raw(i).into(),
                count,
            };
        }

        report
    }

    fn insert_node_into_bin(&mut self, size: u32, data_offset: u32) -> u32 {
        // Round down to bin index to ensure that bin >= alloc
        let bin_index: u32 = SmallFloat::from_u32_round_down(size).raw_value();

        let top_bin_index = bin_index >> TOP_BINS_INDEX_SHIFT;
        let leaf_bin_index = bin_index & LEAF_BINS_INDEX_MASK;

        // Bin was empty before?
        if self.bin_indices[bin_index as usize] == Node::UNUSED {
            // Set bin mask bits
            self.used_bins[top_bin_index as usize] |= 1 << leaf_bin_index;
            self.used_bins_top |= 1 << top_bin_index;
        }

        // Take a freelist node and insert on top of the bin linked list (next = old top)
        let top_node_index = self.bin_indices[bin_index as usize];
        let node_index = self.free_nodes[self.free_offset as usize];
        self.free_offset -= 1;

        self.nodes[node_index as usize] = Node {
            data_offset,
            data_size: size,
            bin_list_next: top_node_index,
            ..Default::default()
        };

        if top_node_index != Node::UNUSED {
            self.nodes[top_node_index as usize].bin_list_prev = node_index;
        }

        self.bin_indices[bin_index as usize] = node_index;

        self.free_storage += size;

        node_index
    }

    fn remove_node_from_bin(&mut self, node_index: u32) {
        let node = self.nodes[node_index as usize].clone();

        if node.bin_list_prev != Node::UNUSED {
            // Easy case: We have previous node. Just remove this node from the middle of the list.
            self.nodes[node.bin_list_prev as usize].bin_list_next = node.bin_list_next;
            if node.bin_list_next != Node::UNUSED {
                self.nodes[node.bin_list_next as usize].bin_list_prev = node.bin_list_prev;
            }
        } else {
            // Hard case: We are the first node in a bin. Find the bin.

            // Round down to bin index to ensure that bin >= alloc
            let bin_index: u32 = SmallFloat::from_u32_round_down(node.data_size).raw_value();

            let top_bin_index = bin_index >> TOP_BINS_INDEX_SHIFT;
            let leaf_bin_index = bin_index & LEAF_BINS_INDEX_MASK;

            self.bin_indices[bin_index as usize] = node.bin_list_next;
            if node.bin_list_next != Node::UNUSED {
                self.nodes[node.bin_list_next as usize].bin_list_prev = Node::UNUSED;
            }

            // Bin empty?
            if self.bin_indices[bin_index as usize] == Node::UNUSED {
                // Remove a leaf bin mask bit
                self.used_bins[top_bin_index as usize] &= !(1 << leaf_bin_index);

                // All leaf bins empty?
                if self.used_bins[top_bin_index as usize] == 0 {
                    // Remove a top bin mask bit
                    self.used_bins_top &= !(1 << top_bin_index);
                }
            }
        }

        // Insert the node to freelist
        self.free_offset += 1;
        self.free_nodes[self.free_offset as usize] = node_index;

        self.free_storage -= node.data_size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_allocator() -> Allocator {
        Allocator::new(1024 * 1024 * 256, Allocator::DEFAULT_MAX_ALLOCS)
    }

    fn check_allocate(allocator: &mut Allocator, size: u32, expected_offset: u32) -> Allocation {
        let allocation = allocator.allocate(size);
        assert!(allocation.is_some());
        let allocation = allocation.unwrap();
        assert_eq!(allocation.offset, expected_offset);
        allocation
    }

    #[test]
    fn basic() {
        let mut allocator = create_allocator();

        let a = check_allocate(&mut allocator, 1337, 0);

        allocator.free(a);
    }

    #[test]
    fn simple() {
        let mut allocator = create_allocator();

        // Free merges neighbor empty nodes. Next allocation should also have offset = 0
        let a = check_allocate(&mut allocator, 0, 0);
        let b = check_allocate(&mut allocator, 1, 0);
        let c = check_allocate(&mut allocator, 123, 1);
        let d = check_allocate(&mut allocator, 1234, 124);

        allocator.free(a);
        allocator.free(b);
        allocator.free(c);
        allocator.free(d);

        // End: Validate that allocator has no fragmentation left. Should be 100% clean.
        let validate_all = check_allocate(&mut allocator, 1024 * 1024 * 256, 0);
        allocator.free(validate_all);
    }

    #[test]
    fn merge() {
        let mut allocator = create_allocator();

        // Free merges neighbor empty nodes. Next allocation should also have offset = 0
        let a = check_allocate(&mut allocator, 1337, 0);
        allocator.free(a);

        let b = check_allocate(&mut allocator, 1337, 0);
        allocator.free(b);

        // End: Validate that allocator has no fragmentation left. Should be 100% clean.
        let validate_all = check_allocate(&mut allocator, 1024 * 1024 * 256, 0);
        allocator.free(validate_all);
    }

    #[test]
    fn reuse_trivial() {
        let mut allocator = create_allocator();

        // Allocator should reuse node freed by A since the allocation C fits in the same bin (using pow2 size to be sure)
        let a = check_allocate(&mut allocator, 1024, 0);
        let b = check_allocate(&mut allocator, 3456, 1024);
        allocator.free(a);

        let c = check_allocate(&mut allocator, 1024, 0);
        allocator.free(c);
        allocator.free(b);

        // End: Validate that allocator has no fragmentation left. Should be 100% clean.
        let validate_all = check_allocate(&mut allocator, 1024 * 1024 * 256, 0);
        allocator.free(validate_all);
    }

    #[test]
    fn reuse_complex() {
        let mut allocator = create_allocator();

        // Allocator should not reuse node freed by A since the allocation C doesn't fits in the same bin
        // However node D and E fit there and should reuse node from A
        let a = check_allocate(&mut allocator, 1024, 0);
        let b = check_allocate(&mut allocator, 3456, 1024);

        allocator.free(a);

        let c = check_allocate(&mut allocator, 2345, 1024 + 3456);
        let d = check_allocate(&mut allocator, 456, 0);
        let e = check_allocate(&mut allocator, 512, 456);

        let report = allocator.storage_report();
        assert_eq!(
            report.total_free_space,
            1024 * 1024 * 256 - 3456 - 2345 - 456 - 512
        );
        assert_ne!(report.largest_free_region, report.total_free_space);

        allocator.free(c);
        allocator.free(d);
        allocator.free(b);
        allocator.free(e);

        // End: Validate that allocator has no fragmentation left. Should be 100% clean.
        let validate_all = check_allocate(&mut allocator, 1024 * 1024 * 256, 0);
        allocator.free(validate_all);
    }

    #[test]
    fn zero_fragmentation() {
        let mut allocator = create_allocator();

        // Allocate 256x 1MB. Should fit. Then free four random slots and reallocate four slots.
        // Plus free four contiguous slots an allocate 4x larger slot. All must be zero fragmentation!
        let mut allocations = [None; 256];
        for (i, allocation) in allocations.iter_mut().enumerate() {
            *allocation = Some(check_allocate(
                &mut allocator,
                1024 * 1024,
                i as u32 * 1024 * 1024,
            ));
        }

        let report = allocator.storage_report();
        assert_eq!(report.total_free_space, 0);
        assert_eq!(report.largest_free_region, 0);

        // Free four random slots
        allocator.free(allocations[243].unwrap());
        allocator.free(allocations[5].unwrap());
        allocator.free(allocations[123].unwrap());
        allocator.free(allocations[95].unwrap());

        // Free four contiguous slot (allocator must merge)
        allocator.free(allocations[151].unwrap());
        allocator.free(allocations[152].unwrap());
        allocator.free(allocations[153].unwrap());
        allocator.free(allocations[154].unwrap());

        allocations[243] = allocator.allocate(1024 * 1024);
        allocations[5] = allocator.allocate(1024 * 1024);
        allocations[123] = allocator.allocate(1024 * 1024);
        allocations[95] = allocator.allocate(1024 * 1024);
        allocations[151] = allocator.allocate(1024 * 1024 * 4); // 4x larger
        assert!(allocations[243].is_some());
        assert!(allocations[5].is_some());
        assert!(allocations[123].is_some());
        assert!(allocations[95].is_some());
        assert!(allocations[151].is_some());

        for i in 0..256 {
            if i < 152 || i > 154 {
                allocator.free(allocations[i].unwrap());
            }
        }

        let report2 = allocator.storage_report();
        assert_eq!(report2.total_free_space, 1024 * 1024 * 256);
        assert_eq!(report2.largest_free_region, 1024 * 1024 * 256);

        // End: Validate that allocator has no fragmentation left. Should be 100% clean.
        let validate_all = check_allocate(&mut allocator, 1024 * 1024 * 256, 0);
        allocator.free(validate_all);
    }
}

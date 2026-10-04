# Secure-storage EPIC — per-story commit and evidence matrix

The story document for this work is `docs/tasks/EPIC-secure-storage.md`, which
is **untracked** (`.gitignore`: `docs/tasks/`). This file is the tracked index of
what actually shipped: every story, the commit that carries it, and the named
test or document that would fail if it were removed.

Regenerate with `git log --oneline 4132c5f..HEAD` against
`docs/tasks/EPIC-secure-storage.md`'s `#### US-XXXX` headings. 43 stories,
fully contiguous.

| Story | Title | Commit(s) | Evidence | Status |
|---|---|---|---|---|
| US-1534 | Flash budget below data window | `d5cb21a` | `tests/scripts/check_flash_budget.py` | verified |
| US-1535 | Reproduce 4-credential ceiling | `50f17f5` | `four_realistic_credentials_persist_with_nine_foreign_slots_resident`, `a_fifth_credential_is_refused_with_key_store_full` — `apps/fido/tests/key_store_ceiling.rs` | verified |
| US-1536 | Trussed FS above the budget | `e9bc670` | `the_trussed_window_sits_in_the_headroom_not_the_firmware_budget` — `platform/tests/flash_map.rs`; `the_file_level_migration_preserves_a_populated_legacy_volume` — `fs_store_backing.rs` | verified |
| US-1537 | Assert every key's storage location | `22c8cf5`, `ebe923e` | `the_opcard_default_storage_is_never_volatile`, `no_production_site_puts_card_state_on_the_volatile_filesystem`, `the_private_key_is_only_ever_persisted_wrapped` — `apps/openpgp/tests/key_storage_location.rs` | verified (source audit) |
| US-1538 | Back `Location::External` with flash | `623e52e`, `d1eea9f` | `external_resolves_to_flash_on_the_device` — `fs_store_backing.rs`; `a_generated_key_survives_a_power_cycle_on_the_generate_path` — `apps/openpgp/tests/device_pso.rs` | verified |
| US-1539 | Reserve the key region in the linker script | `4be8fe1` | `the_region_is_where_the_linker_script_says_it_is` — `platform/tests/key_region_capacity.rs` | verified |
| US-1540 | Derive capacity from the region | `7036973`, `b02ba66` | `the_capacities_are_the_region_arithmetic` — `key_region_capacity.rs` | verified |
| US-1541 | Host backend for the key region | `587ea10`, `476e467` | `records_written_and_read_back_are_byte_identical` — `key_region_host.rs`; `a_mixed_script_leaves_both_regions_identical` — `key_region_device_nor.rs` | verified |
| US-1542 | Record codec with a CRC header | `9ab862e` | `flipping_one_header_bit_fails_the_crc`, `a_record_round_trips_and_every_field_is_recovered_byte_identically` — `platform/tests/record_codec.rs` | verified |
| US-1543 | Slot allocator, monotonic generation | `587ea10` | `allocation_takes_the_lowest_free_slot`, `the_scan_is_bounded_by_the_compile_time_slot_count` — `key_region_host.rs` | verified |
| US-1544 | Atomic single-record commit | `3038aff`, `b8128c2` | `an_update_erases_exactly_one_sector_and_writes_the_commit_marker_last` — `key_region_commit.rs` | verified (restated) |
| US-1545 | Failed commit is self-cleaning | `3038aff` | `a_failure_before_the_erase_removes_this_calls_records_and_keeps_generation_n` — `key_region_commit.rs` | verified |
| US-1546 | Wipe and factory reset | `3038aff`, `7a1fd11` | `a_reset_erases_every_fido_record_slot_and_the_whole_index`, `a_reset_leaves_oaths_credentials_alone`, `a_reset_whose_erase_fails_is_refused_and_keeps_the_credential` — `apps/fido/tests/reset_wipes_region.rs` | verified (restated) |
| US-1547 | One root, two subkeys | `587ea10` | `the_index_key_is_hkdf_over_the_otp_row_and_chip_id_only` — `platform/tests/key_region_crypto.rs` | verified |
| US-1548 | AAD binds slot, generation, domain | `587ea10` | `a_record_cannot_be_replayed_into_another_slot_generation_or_domain` — `record_codec.rs` | verified |
| US-1549 | Per-record AEAD, fail-closed | `9ab862e` | `one_corrupt_record_does_not_lose_the_others`, `a_failed_unseal_leaves_no_partial_plaintext` — `record_codec.rs` | verified |
| US-1550 | Zeroize key material | `301bb31`, `533ef37`, `314a74d`, `3bc0f58` | `no_private_key_is_resident_between_commands`, `a_scalar_cannot_be_copied_or_cloned_by_accident` — `apps/fido/tests/credential_zeroize.rs` | verified |
| US-1551 | Index verifiable without the PIN | `3038aff` | `an_index_written_by_a_device_with_a_pin_set_verifies_with_only_the_otp_row_and_chip_id`, `a_dump_yields_no_credential_id_rp_name_user_name_or_key_material` — `key_region_index.rs` | verified |
| US-1552 | FIDO credentials → key region | `5113ee9` | `the_other_four_credentials_are_byte_identical_afterwards` — `apps/fido/tests/key_region_one_record.rs` | verified |
| US-1553 | OATH credentials → key region | `5113ee9`, `91dfe74`, `d904aac` | `fido_and_oath_at_capacity_coexist` — `apps/oath/tests/oath_keyregion.rs`; `the_oath_provider_is_installed_after_rung_usb` — `platform/tests/key_region_boot_gate.rs` | verified |
| US-1554 | Read one key on demand | `3038aff`, `db8b560` | `exactly_one_record_is_decrypted`, `the_buffer_is_zeroized_after_use` — `key_region_on_demand.rs` | verified |
| US-1555 | credMgmt enumerates from the index | `db8b560`, `93b2c3f` | `the_picoforge_dialect_is_pinned_on_both_twins` — `twin_parity.rs`; `an_update_renames_the_credential_in_the_same_slot` — `region_update_credential.rs` | verified |
| US-1556 | Delete, tombstone, compaction | `db8b560` | `deleting_a_credential_frees_its_slot_and_a_later_enrolment_reuses_it` — `region_delete_compaction.rs` | verified |
| US-1557 | Device/host twin parity | `301bb31` | `the_two_twins_answer_the_same_script_identically`, `the_capacity_divergence_is_explicit_not_incidental` — `twin_parity.rs` | verified (restated) |
| US-1558 | Migrate existing stores | `7e05582` | `every_snapshot_credential_becomes_its_own_record`, `an_interrupted_migration_leaves_the_snapshot_intact_and_re_runs` — `snapshot_migration.rs` | verified |
| US-1559 | Index built after `RUNG_USB` | `476e467`, `d904aac` | `no_boot_path_call_site_reaches_the_accessor_before_rung_usb`, `the_only_pre_usb_region_mention_is_the_handle_construction` — `key_region_boot_gate.rs` | verified (source audit) |
| US-1560 | Failure degrades to an empty key set | `7e05582` | `an_unreadable_region_degrades_to_an_empty_key_set`, `no_new_halt_site_is_reachable_from_the_key_region` — `apps/fido/tests/region_degradation.rs` | verified |
| US-1561 | Batch counter bumps | `301bb31`, `3bc0f58` | `thirty_one_assertions_erase_nothing`, `the_32nd_assertion_erases_one_live_sector_and_reprograms_it` — `region_counter_batching.rs` | verified |
| US-1562 | Re-derive the erase budget | `301bb31`, `2953675` | `tests/scripts/check_erase_budget.py::record_failures`; `docs/erase-budget.md` §4c | verified (doc + gate) |
| US-1563 | Capacity measured at the boundary | `db8b560` | `the_boundary_is_the_derived_capacity_and_the_next_enrolment_is_refused` — `apps/fido/tests/capacity_boundary.rs` | verified |
| US-1564 | Capacity constants derived | `301bb31`, `9dafe9b` | `the_capacity_document_does_not_present_a_constant_as_a_capacity` — `capacity_boundary.rs` | verified |
| US-1565 | Re-baseline the size report | `119304a`, `0c70e81`, `a2f4a7b`, `d904aac` | `tests/scripts/check_size_report.py`; `docs/size-report.md` | verified (doc + gate) |
| US-1566 | Correct the wrong-number docs | `17d3228`, `9336984` | `docs/capacity.md` §"Four acceptance criteria that had to be restated"; read by the US-1563 gate | verified (doc) |
| US-1567 | Provisioning policy ADR | `4f24bc3` | `docs/adr/0002-provisioning-policy.md`, indexed in `docs/adr/README.md` | verified (doc) |
| US-1568 | Tag convention applied | `4f24bc3` | `docs/adr/0002-provisioning-policy.md` §Tag convention | verified (doc) |
| US-1569 | no_std hardware SHA-256 driver | `4e82309` | `the_required_padding_boundary_set`, `the_driver_uses_core_only` — `platform/tests/sha256_accel.rs` | verified |
| US-1570 | PIN KDF on the accelerator | `7e05582` | `the_round_count_fits_the_budget_under_the_pessimistic_cost_model`, `the_legacy_migration_window_is_a_single_comparison_and_it_gates_admission` — `apps/fido/tests/pin_kdf_budget.rs` | verified |
| US-1571 | Retry-counter power-cut properties | `7e05582` | `the_durable_retry_count_is_never_higher_than_the_pre_attempt_count` — `apps/fido/tests/retry_counter_power_cut.rs` | verified |
| US-1572 | No resident session keys | `5113ee9`, `cd6599a` | `each_use_reads_derives_and_drops` — `platform/tests/fused_key.rs` | **partial** — see below |
| US-1573 | Fail-closed fault semantics | `9583c39` | `a_faulted_read_is_distinguishable_from_an_absent_one`, `a_region_fault_is_not_reported_as_an_empty_region` — `region_degradation.rs` | verified (restated) |
| US-1574 | Type-level key-slot chokepoint | `9583c39` | three `compile_fail` doctests at `platform/src/keyregion/mod.rs` | verified (compile-fail) |
| US-1575 | Domain-separate `DEVICE/ROOT` | `7655dc9` | `the_bound_root_and_the_c_root_do_not_share_an_info_label`, `no_two_derivations_share_a_salt_and_info_pair` — `platform/tests/ckey_kbase.rs` | verified |
| US-1576 | TrustZone ADR | `4f24bc3` | `docs/adr/0003-trustzone.md`, indexed in `docs/adr/README.md` | verified (doc) |

**41 verified, 1 partial, 0 unverified.**

## The partial: US-1572

The store key is fused and tested. The BDD's second half — the OATH seal
becoming a per-operation read — is not done, and it is not "the same
conversion". `FusedKey` fuses **one** `[u8; 32]` per operation, which works for
the store key because the store has a medium to read it back from — its own
encrypted image. `OathSeal` has no such medium and is not one value: it is a
three-field derived struct (`platform/src/ckey.rs:394-402`). Converting it needs
a container for a derived *struct*, and changes every `self.seal.*` use site in
`apps/oath`.

The exposure it would remove is bounded and stated: 16 bytes plus a nonce root,
resident for one session and cleared on drop. The store key was the larger
exposure and is the one US-1572 closed. Recorded in `platform/src/fused_key.rs`
and in [`capacity.md`](capacity.md) §"Two stories that shipped partly".

## Four BDDs reconciled rather than met as written

Recorded in [`capacity.md`](capacity.md) §"Four acceptance criteria that had to be
restated" (`9336984`), because the epic itself is untracked.

| Story | As written | Why it cannot be |
|---|---|---|
| US-1544 | "exactly one erase and one program" | NOR cannot rewrite programmed bytes; `SLOTS_PER_SECTOR` slots share one 4 KiB sector. Restated at sector granularity. |
| US-1546 | "FIDO, OATH **and OpenPGP** records"; "every slot is erased" | OpenPGP keys are not in the key region, and a FIDO-scoped reset erasing every slot would destroy OATH's. Now `wipe_fido_range`. |
| US-1557 | both twins "report the same capacity" | The host twin's capacity is a RAM-array property and its store cannot reach the region. The test now asserts the divergence. |
| US-1573 | "every absent-arm that writes takes a `try_*` probe" | RS-Key's own docs reject that derivation method (`fs.rs:352-364`). The store is stateless, so there is nothing to memoize a fault into. |

## Bugs found after their stories shipped

Six of the stories were followed by a fix commit for a defect in the same area.
Each fix is separate because each is independently reviewable, and each is
mutation-verified — the test named in the row fails when the fix is reverted.

| Fix | Story | Defect |
|---|---|---|
| `3cf0b56` | US-1552/1561 | Two ways a FIDO write could destroy a credential it never named: a one-sided slot guard once OATH took the region's head, and an index splice applied to all four slots of a sector. |
| `93b2c3f` | US-1555 | A credMgmt rename went through `put`, allocating a second slot per rename and leaving the old record live. |
| `7a1fd11` | US-1546 | `authenticatorReset` cleared the in-RAM snapshot and nothing else — every FIDO record stayed on flash, and the PIN-free index kept reporting the pre-reset count. |
| `2953675` | US-1562 | The splice fix was costing six slot programs per counter write; `check_erase_budget.py` caught a correctness defect as a wear regression. |
| `b8128c2` | US-1544 | A commit could name an index slot as its scratchpad and erase the index on every write, returning `Ok` throughout. |
| `d904aac` | US-1553 | OATH's 68 reserved slots had no firmware call site, so the region partition the epic reserved was flash nothing read. |

## Related

* [`capacity.md`](capacity.md) — measured ceilings, the derived/claimed
  distinction, and the reconciled acceptance criteria.
* [`erase-budget.md`](erase-budget.md) §4c — per-record wear, measured.
* [`docs/adr/0002-provisioning-policy.md`](adr/0002-provisioning-policy.md),
  [`docs/adr/0003-trustzone.md`](adr/0003-trustzone.md) — US-1567, US-1576.
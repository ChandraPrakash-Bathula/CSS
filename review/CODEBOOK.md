# Extraction codebook

One row per included paper in `extraction_template.csv`. Use **only** the listed codes.
If the paper doesn't say, code `not_reported`. Never infer. Put page/section evidence in
the matching `*_evidence` column (a quote or "Sec 4.2, Tab 3"); κ is meaningless without it.

| field | codes | notes |
|---|---|---|
| `paper_id` | from `candidates.csv` | |
| `year` | yyyy | |
| `venue_type` | `journal` `conference` `workshop` `preprint` | |
| `model_family` | `classical_ml` `deep_learning` `transformer` `llm` `hybrid` | the main proposed model |
| `input_unit` | `payload_string` `url` `http_request` `http_response` `js_code` `dom` `other` | what the model scores |
| `datasets` | `;`-separated names from `datasets_vocab.csv` (add new names there) | e.g. `kaggle_syedsaqlainhussain;payloadbox` |
| `dataset_size_pos`, `dataset_size_neg` | integers or `not_reported` | as used, after paper's filtering |
| `label_source` | `inherited` `regex_or_waf` `manual` `execution_verified` `generated_assumed_malicious` `mixed` | how *positives* became positives |
| `execution_check` | `none` `subset` `all` | did a browser/JS engine confirm positives run? |
| `execution_check_method` | `none` `alert_hook` `marker` `taint` `manual` `other` | |
| `benign_source` | `crawl` `dataset` `generated` `manual` `not_reported` | |
| `dedup` | `none` `exact` `near_duplicate` `not_reported` | |
| `split` | `random_row` `kfold_row` `grouped` `temporal` `cross_dataset` `not_reported` | `grouped` = families/variants kept together |
| `headline_metric` | `accuracy` `f1` `precision_recall` `auc` `other` | the number in the abstract |
| `headline_value` | number as printed | |
| `robustness_test` | `none` `obfuscation` `adversarial` `cross_dataset` `multiple` | |
| `evasion_execution_checked` | `n_a` `no` `yes` | if evasion/obfuscation was tested: were evading payloads checked to still execute? |
| `baselines` | `none` `own_variants` `published_ml` `waf_rules` `multiple` | |
| `placement_discussed` | `no` `request_side` `response_side` `browser` `multiple` | |
| `xss_types` | `reflected` `stored` `dom` `unspecified` (`;`-separated) | |
| `code_released` | `yes` `no` | a working link in the paper |
| `data_released` | `yes` `no` `public_dataset_only` | |
| `notes` | free text | |

## Decision rules
- **`label_source = inherited`** when positives come straight from a public list or dataset with no further check, *even if* the paper calls them "real attacks".
- **`execution_verified`** only if the paper says each positive (or a stated subset → `execution_check = subset`) was run in a browser or JS engine and observed to execute.
- **`generated_assumed_malicious`**: payloads produced by GAN/LLM/mutation and counted as attacks without execution.
- **Split:** reporting "80/20" with no mention of grouping is `random_row`. "5-fold CV" without grouping is `kfold_row`.

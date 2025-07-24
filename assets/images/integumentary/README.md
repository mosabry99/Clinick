# Integumentary Images

This folder stores every **PNG** illustration used by integumentary care-plans in the Clinick application.

## Naming convention

1. **File name exactly matches the care-plan title written in Title Case.**  
   • Omit trailing words such as **“Management”**, **“Care”**, or **“Plan”**.  
   • Preserve spaces between words (do **not** replace them with underscores or hyphens).  
   • Retain any clinically relevant punctuation that appears inside the original title (e.g., parentheses, colons).  
2. Use the `.png` file extension (lower-case).  
3. Save the file directly in `assets/images/integumentary/`.  
4. When new integumentary care-plans are added (IDs will **begin at in006** and continue sequentially), create the corresponding image following these rules **before** adding the JSON entry.

Example  
Care-plan title: **“Impaired Skin Integrity Management”**  
Image file: `Impaired Skin Integrity.png`

---

## Current required images

As of the latest update the integumentary category includes five active plans (IDs **in001 – in005**). Make sure each of them has a matching image stored here.  
_Update the table whenever plans are added or removed._

| Care-plan title (trimmed)      | Expected image file                    | Present? |
| ------------------------------ | -------------------------------------- | -------- |
| _Add rows for each plan_       |                                        |          |

---

## Contributor checklist

- [ ] Verify the image follows the naming convention above.  
- [ ] Confirm a suitable resolution for both mobile and web (≥ 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README whenever images are added or care-plans are removed.  
- [ ] For any new integumentary plan, remember its ID must start at **in006** or the next available sequential number.

Thank you for helping keep our integumentary media assets organized and consistent!

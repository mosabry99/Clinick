# Cardiovascular Images

This folder stores all **PNG** illustrations used by cardiovascular care-plans in the Clinick app.

## Naming convention

1. File name **exactly matches** the care-plan title written in Title Case.  
   • Omit any trailing words such as “Management”, “Care”, or “Plan”.  
   • Keep spaces as spaces; do **not** use underscores or hyphens.  
   • Retain clinically relevant punctuation (e.g., colons) only if it appears inside the title; otherwise remove it.  
2. All files use the `.png` extension.  
3. Place the file directly in `assets/images/cardiovascular/`.  
4. When a new cardiovascular care-plan is created (IDs will start at **cv006** and continue sequentially), create its image using the same rules and add it to this folder.

Example  
Care-plan title: **“Decreased Cardiac Output Management”**  
Image file: `Decreased Cardiac Output.png`

## Current required images

As of the latest update the cardiovascular category includes three active plans. Ensure each of the following images is present:

| Care-plan title (trimmed) | Expected image file |
| ------------------------- | ------------------- |
| Decreased Cardiac Output  | `Decreased Cardiac Output.png` |
| Excess Fluid Volume       | `Excess Fluid Volume.png` |
| Activity Intolerance      | `Activity Intolerance.png` |

## Contributor checklist

- [ ] Verify the image follows the naming convention above.  
- [ ] Confirm the image resolution is appropriate for both mobile and web (minimum 800 × 600 px recommended).  
- [ ] Optimize file size (< 300 KB preferred) without visible quality loss.  
- [ ] Commit the image **before** referencing it in the care-plan JSON.  
- [ ] Update this README if new images are added or care-plans are removed.

Thank you for keeping our media assets tidy and consistent!

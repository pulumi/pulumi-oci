// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Masking Reports Masked Column resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets a list of masked columns present in the specified masking report and based on the specified query parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMaskingReportsMaskedColumn = oci.DataSafe.getMaskingReportsMaskedColumn({
 *     maskingReportId: oci_data_safe_masking_report.test_masking_report.id,
 *     columnNames: _var.masking_reports_masked_column_column_name,
 *     maskingColumnGroups: _var.masking_reports_masked_column_masking_column_group,
 *     objects: _var.masking_reports_masked_column_object,
 *     objectTypes: _var.masking_reports_masked_column_object_type,
 *     schemaNames: _var.masking_reports_masked_column_schema_name,
 *     sensitiveTypeId: oci_data_safe_sensitive_type.test_sensitive_type.id,
 * });
 * ```
 */
export function getMaskingReportsMaskedColumn(args: GetMaskingReportsMaskedColumnArgs, opts?: pulumi.InvokeOptions): Promise<GetMaskingReportsMaskedColumnResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DataSafe/getMaskingReportsMaskedColumn:getMaskingReportsMaskedColumn", {
        "columnNames": args.columnNames,
        "maskingColumnGroups": args.maskingColumnGroups,
        "maskingReportId": args.maskingReportId,
        "objectTypes": args.objectTypes,
        "objects": args.objects,
        "schemaNames": args.schemaNames,
        "sensitiveTypeId": args.sensitiveTypeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMaskingReportsMaskedColumn.
 */
export interface GetMaskingReportsMaskedColumnArgs {
    /**
     * A filter to return only a specific column based on column name.
     */
    columnNames?: string[];
    /**
     * A filter to return only the resources that match the specified masking column group.
     */
    maskingColumnGroups?: string[];
    /**
     * The OCID of the masking report.
     */
    maskingReportId: string;
    /**
     * A filter to return only items related to a specific object type.
     */
    objectTypes?: string[];
    /**
     * A filter to return only items related to a specific object name.
     */
    objects?: string[];
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: string[];
    /**
     * A filter to return only items related to a specific sensitive type OCID.
     */
    sensitiveTypeId?: string;
}

/**
 * A collection of values returned by getMaskingReportsMaskedColumn.
 */
export interface GetMaskingReportsMaskedColumnResult {
    /**
     * The name of the masked column.
     */
    readonly columnNames?: string[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * An array of masking column summary objects.
     */
    readonly items: outputs.DataSafe.GetMaskingReportsMaskedColumnItem[];
    /**
     * The masking group of the masked column.
     */
    readonly maskingColumnGroups?: string[];
    readonly maskingReportId: string;
    /**
     * The type of the object (table or editioning view) that contains the masked column.
     */
    readonly objectTypes?: string[];
    /**
     * The name of the object (table or editioning view) that contains the masked column.
     */
    readonly objects?: string[];
    /**
     * The name of the schema that contains the masked column.
     */
    readonly schemaNames?: string[];
    /**
     * The OCID of the sensitive type associated with the masked column.
     */
    readonly sensitiveTypeId?: string;
}

export function getMaskingReportsMaskedColumnOutput(args: GetMaskingReportsMaskedColumnOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetMaskingReportsMaskedColumnResult> {
    return pulumi.output(args).apply(a => getMaskingReportsMaskedColumn(a, opts))
}

/**
 * A collection of arguments for invoking getMaskingReportsMaskedColumn.
 */
export interface GetMaskingReportsMaskedColumnOutputArgs {
    /**
     * A filter to return only a specific column based on column name.
     */
    columnNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only the resources that match the specified masking column group.
     */
    maskingColumnGroups?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The OCID of the masking report.
     */
    maskingReportId: pulumi.Input<string>;
    /**
     * A filter to return only items related to a specific object type.
     */
    objectTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to a specific object name.
     */
    objects?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to specific schema name.
     */
    schemaNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A filter to return only items related to a specific sensitive type OCID.
     */
    sensitiveTypeId?: pulumi.Input<string>;
}
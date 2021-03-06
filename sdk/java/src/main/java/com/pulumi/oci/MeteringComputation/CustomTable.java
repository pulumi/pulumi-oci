// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.MeteringComputation.CustomTableArgs;
import com.pulumi.oci.MeteringComputation.inputs.CustomTableState;
import com.pulumi.oci.MeteringComputation.outputs.CustomTableSavedCustomTable;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Custom Table resource in Oracle Cloud Infrastructure Metering Computation service.
 * 
 * Returns the created custom table.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * CustomTables can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:MeteringComputation/customTable:CustomTable test_custom_table &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:MeteringComputation/customTable:CustomTable")
public class CustomTable extends com.pulumi.resources.CustomResource {
    /**
     * The compartment OCID.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The compartment OCID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) The custom table for Cost Analysis UI rendering.
     * 
     */
    @Export(name="savedCustomTable", type=CustomTableSavedCustomTable.class, parameters={})
    private Output<CustomTableSavedCustomTable> savedCustomTable;

    /**
     * @return (Updatable) The custom table for Cost Analysis UI rendering.
     * 
     */
    public Output<CustomTableSavedCustomTable> savedCustomTable() {
        return this.savedCustomTable;
    }
    /**
     * The associated saved report OCID.
     * 
     */
    @Export(name="savedReportId", type=String.class, parameters={})
    private Output<String> savedReportId;

    /**
     * @return The associated saved report OCID.
     * 
     */
    public Output<String> savedReportId() {
        return this.savedReportId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public CustomTable(String name) {
        this(name, CustomTableArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public CustomTable(String name, CustomTableArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public CustomTable(String name, CustomTableArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:MeteringComputation/customTable:CustomTable", name, args == null ? CustomTableArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private CustomTable(String name, Output<String> id, @Nullable CustomTableState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:MeteringComputation/customTable:CustomTable", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static CustomTable get(String name, Output<String> id, @Nullable CustomTableState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new CustomTable(name, id, state, options);
    }
}

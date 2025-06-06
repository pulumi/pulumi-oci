// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.ComputeImageCapabilitySchemaArgs;
import com.pulumi.oci.Core.inputs.ComputeImageCapabilitySchemaState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Compute Image Capability Schema resource in Oracle Cloud Infrastructure Core service.
 * 
 * Creates compute image capability schema.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * ComputeImageCapabilitySchemas can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Core/computeImageCapabilitySchema:ComputeImageCapabilitySchema test_compute_image_capability_schema &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Core/computeImageCapabilitySchema:ComputeImageCapabilitySchema")
public class ComputeImageCapabilitySchema extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the compartment that contains the resource.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment that contains the resource.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The ocid of the compute global image capability schema
     * 
     */
    @Export(name="computeGlobalImageCapabilitySchemaId", refs={String.class}, tree="[0]")
    private Output<String> computeGlobalImageCapabilitySchemaId;

    /**
     * @return The ocid of the compute global image capability schema
     * 
     */
    public Output<String> computeGlobalImageCapabilitySchemaId() {
        return this.computeGlobalImageCapabilitySchemaId;
    }
    /**
     * The name of the compute global image capability schema version
     * 
     */
    @Export(name="computeGlobalImageCapabilitySchemaVersionName", refs={String.class}, tree="[0]")
    private Output<String> computeGlobalImageCapabilitySchemaVersionName;

    /**
     * @return The name of the compute global image capability schema version
     * 
     */
    public Output<String> computeGlobalImageCapabilitySchemaVersionName() {
        return this.computeGlobalImageCapabilitySchemaVersionName;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The ocid of the image
     * 
     */
    @Export(name="imageId", refs={String.class}, tree="[0]")
    private Output<String> imageId;

    /**
     * @return The ocid of the image
     * 
     */
    public Output<String> imageId() {
        return this.imageId;
    }
    /**
     * (Updatable) The map of each capability name to its ImageCapabilitySchemaDescriptor.
     * 
     */
    @Export(name="schemaData", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> schemaData;

    /**
     * @return (Updatable) The map of each capability name to its ImageCapabilitySchemaDescriptor.
     * 
     */
    public Output<Map<String,String>> schemaData() {
        return this.schemaData;
    }
    /**
     * The date and time the compute image capability schema was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The date and time the compute image capability schema was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ComputeImageCapabilitySchema(java.lang.String name) {
        this(name, ComputeImageCapabilitySchemaArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ComputeImageCapabilitySchema(java.lang.String name, ComputeImageCapabilitySchemaArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ComputeImageCapabilitySchema(java.lang.String name, ComputeImageCapabilitySchemaArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/computeImageCapabilitySchema:ComputeImageCapabilitySchema", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ComputeImageCapabilitySchema(java.lang.String name, Output<java.lang.String> id, @Nullable ComputeImageCapabilitySchemaState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/computeImageCapabilitySchema:ComputeImageCapabilitySchema", name, state, makeResourceOptions(options, id), false);
    }

    private static ComputeImageCapabilitySchemaArgs makeArgs(ComputeImageCapabilitySchemaArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ComputeImageCapabilitySchemaArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
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
    public static ComputeImageCapabilitySchema get(java.lang.String name, Output<java.lang.String> id, @Nullable ComputeImageCapabilitySchemaState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ComputeImageCapabilitySchema(name, id, state, options);
    }
}

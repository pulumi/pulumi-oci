// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataScience.ModelArgs;
import com.pulumi.oci.DataScience.inputs.ModelState;
import com.pulumi.oci.DataScience.outputs.ModelCustomMetadataList;
import com.pulumi.oci.DataScience.outputs.ModelDefinedMetadataList;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Model resource in Oracle Cloud Infrastructure Data Science service.
 * 
 * Creates a new model.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * Models can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:DataScience/model:Model test_model &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DataScience/model:Model")
public class Model extends com.pulumi.resources.CustomResource {
    @Export(name="artifactContentDisposition", type=String.class, parameters={})
    private Output<String> artifactContentDisposition;

    public Output<String> artifactContentDisposition() {
        return this.artifactContentDisposition;
    }
    @Export(name="artifactContentLength", type=String.class, parameters={})
    private Output<String> artifactContentLength;

    public Output<String> artifactContentLength() {
        return this.artifactContentLength;
    }
    @Export(name="artifactContentMd5", type=String.class, parameters={})
    private Output<String> artifactContentMd5;

    public Output<String> artifactContentMd5() {
        return this.artifactContentMd5;
    }
    @Export(name="artifactLastModified", type=String.class, parameters={})
    private Output<String> artifactLastModified;

    public Output<String> artifactLastModified() {
        return this.artifactLastModified;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model in.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model in.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model.
     * 
     */
    @Export(name="createdBy", type=String.class, parameters={})
    private Output<String> createdBy;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model.
     * 
     */
    public Output<String> createdBy() {
        return this.createdBy;
    }
    /**
     * (Updatable) An array of custom metadata details for the model.
     * 
     */
    @Export(name="customMetadataLists", type=List.class, parameters={ModelCustomMetadataList.class})
    private Output<List<ModelCustomMetadataList>> customMetadataLists;

    /**
     * @return (Updatable) An array of custom metadata details for the model.
     * 
     */
    public Output<List<ModelCustomMetadataList>> customMetadataLists() {
        return this.customMetadataLists;
    }
    /**
     * (Updatable) An array of defined metadata details for the model.
     * 
     */
    @Export(name="definedMetadataLists", type=List.class, parameters={ModelDefinedMetadataList.class})
    private Output<List<ModelDefinedMetadataList>> definedMetadataLists;

    /**
     * @return (Updatable) An array of defined metadata details for the model.
     * 
     */
    public Output<List<ModelDefinedMetadataList>> definedMetadataLists() {
        return this.definedMetadataLists;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) A short description of the model.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) A short description of the model.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My Model`
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My Model`
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    @Export(name="emptyModel", type=Boolean.class, parameters={})
    private Output<Boolean> emptyModel;

    public Output<Boolean> emptyModel() {
        return this.emptyModel;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * Input schema file content in String format
     * 
     */
    @Export(name="inputSchema", type=String.class, parameters={})
    private Output<String> inputSchema;

    /**
     * @return Input schema file content in String format
     * 
     */
    public Output<String> inputSchema() {
        return this.inputSchema;
    }
    @Export(name="modelArtifact", type=String.class, parameters={})
    private Output<String> modelArtifact;

    public Output<String> modelArtifact() {
        return this.modelArtifact;
    }
    /**
     * Output schema file content in String format
     * 
     */
    @Export(name="outputSchema", type=String.class, parameters={})
    private Output<String> outputSchema;

    /**
     * @return Output schema file content in String format
     * 
     */
    public Output<String> outputSchema() {
        return this.outputSchema;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     * 
     */
    @Export(name="projectId", type=String.class, parameters={})
    private Output<String> projectId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }
    /**
     * The state of the model.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The state of the model.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Model(String name) {
        this(name, ModelArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Model(String name, ModelArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Model(String name, ModelArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataScience/model:Model", name, args == null ? ModelArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Model(String name, Output<String> id, @Nullable ModelState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataScience/model:Model", name, state, makeResourceOptions(options, id));
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
    public static Model get(String name, Output<String> id, @Nullable ModelState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Model(name, id, state, options);
    }
}

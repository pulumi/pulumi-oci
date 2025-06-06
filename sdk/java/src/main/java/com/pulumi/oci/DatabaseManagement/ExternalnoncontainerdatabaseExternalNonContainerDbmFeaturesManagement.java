// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseManagement.ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementState;
import com.pulumi.oci.DatabaseManagement.outputs.ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementFeatureDetails;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * This resource provides the Externalnoncontainerdatabase External Non Container Dbm Features Management resource in Oracle Cloud Infrastructure Database Management service.
 * 
 * Enables Database Management feature for the specified external non-container database.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 */
@ResourceType(type="oci:DatabaseManagement/externalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement:ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement")
public class ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="enableExternalNonContainerDbmFeature", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> enableExternalNonContainerDbmFeature;

    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Boolean> enableExternalNonContainerDbmFeature() {
        return this.enableExternalNonContainerDbmFeature;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external non-container database.
     * 
     */
    @Export(name="externalNonContainerDatabaseId", refs={String.class}, tree="[0]")
    private Output<String> externalNonContainerDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external non-container database.
     * 
     */
    public Output<String> externalNonContainerDatabaseId() {
        return this.externalNonContainerDatabaseId;
    }
    /**
     * The details required to enable the specified Database Management feature.
     * 
     */
    @Export(name="featureDetails", refs={ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementFeatureDetails.class}, tree="[0]")
    private Output<ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementFeatureDetails> featureDetails;

    /**
     * @return The details required to enable the specified Database Management feature.
     * 
     */
    public Output<ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementFeatureDetails> featureDetails() {
        return this.featureDetails;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement(java.lang.String name) {
        this(name, ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement(java.lang.String name, ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement(java.lang.String name, ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement:ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement(java.lang.String name, Output<java.lang.String> id, @Nullable ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement:ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementArgs makeArgs(ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementArgs.Empty : args;
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
    public static ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExternalnoncontainerdatabaseExternalNonContainerDbmFeaturesManagement(name, id, state, options);
    }
}

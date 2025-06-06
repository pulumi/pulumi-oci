// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DatabaseManagement.ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementState;
import com.pulumi.oci.DatabaseManagement.outputs.ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetails;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Externalcontainerdatabase External Container Dbm Features Management resource in Oracle Cloud Infrastructure Database Management service.
 * 
 * Enables a Database Management feature for the specified external container database.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 */
@ResourceType(type="oci:DatabaseManagement/externalcontainerdatabaseExternalContainerDbmFeaturesManagement:ExternalcontainerdatabaseExternalContainerDbmFeaturesManagement")
public class ExternalcontainerdatabaseExternalContainerDbmFeaturesManagement extends com.pulumi.resources.CustomResource {
    @Export(name="canDisableAllPdbs", refs={Boolean.class}, tree="[0]")
    private Output</* @Nullable */ Boolean> canDisableAllPdbs;

    public Output<Optional<Boolean>> canDisableAllPdbs() {
        return Codegen.optional(this.canDisableAllPdbs);
    }
    /**
     * (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="enableExternalContainerDbmFeature", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> enableExternalContainerDbmFeature;

    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<Boolean> enableExternalContainerDbmFeature() {
        return this.enableExternalContainerDbmFeature;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external container database.
     * 
     */
    @Export(name="externalContainerDatabaseId", refs={String.class}, tree="[0]")
    private Output<String> externalContainerDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external container database.
     * 
     */
    public Output<String> externalContainerDatabaseId() {
        return this.externalContainerDatabaseId;
    }
    @Export(name="feature", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> feature;

    public Output<Optional<String>> feature() {
        return Codegen.optional(this.feature);
    }
    /**
     * The details required to enable the specified Database Management feature.
     * 
     */
    @Export(name="featureDetails", refs={ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetails.class}, tree="[0]")
    private Output<ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetails> featureDetails;

    /**
     * @return The details required to enable the specified Database Management feature.
     * 
     */
    public Output<ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetails> featureDetails() {
        return this.featureDetails;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ExternalcontainerdatabaseExternalContainerDbmFeaturesManagement(java.lang.String name) {
        this(name, ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ExternalcontainerdatabaseExternalContainerDbmFeaturesManagement(java.lang.String name, ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ExternalcontainerdatabaseExternalContainerDbmFeaturesManagement(java.lang.String name, ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalcontainerdatabaseExternalContainerDbmFeaturesManagement:ExternalcontainerdatabaseExternalContainerDbmFeaturesManagement", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ExternalcontainerdatabaseExternalContainerDbmFeaturesManagement(java.lang.String name, Output<java.lang.String> id, @Nullable ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DatabaseManagement/externalcontainerdatabaseExternalContainerDbmFeaturesManagement:ExternalcontainerdatabaseExternalContainerDbmFeaturesManagement", name, state, makeResourceOptions(options, id), false);
    }

    private static ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementArgs makeArgs(ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementArgs.Empty : args;
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
    public static ExternalcontainerdatabaseExternalContainerDbmFeaturesManagement get(java.lang.String name, Output<java.lang.String> id, @Nullable ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ExternalcontainerdatabaseExternalContainerDbmFeaturesManagement(name, id, state, options);
    }
}

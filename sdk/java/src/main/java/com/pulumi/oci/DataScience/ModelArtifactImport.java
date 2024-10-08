// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataScience.ModelArtifactImportArgs;
import com.pulumi.oci.DataScience.inputs.ModelArtifactImportState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

@ResourceType(type="oci:DataScience/modelArtifactImport:ModelArtifactImport")
public class ModelArtifactImport extends com.pulumi.resources.CustomResource {
    @Export(name="artifactSourceType", refs={String.class}, tree="[0]")
    private Output<String> artifactSourceType;

    public Output<String> artifactSourceType() {
        return this.artifactSourceType;
    }
    @Export(name="destinationBucket", refs={String.class}, tree="[0]")
    private Output<String> destinationBucket;

    public Output<String> destinationBucket() {
        return this.destinationBucket;
    }
    @Export(name="destinationObjectName", refs={String.class}, tree="[0]")
    private Output<String> destinationObjectName;

    public Output<String> destinationObjectName() {
        return this.destinationObjectName;
    }
    @Export(name="destinationRegion", refs={String.class}, tree="[0]")
    private Output<String> destinationRegion;

    public Output<String> destinationRegion() {
        return this.destinationRegion;
    }
    @Export(name="modelId", refs={String.class}, tree="[0]")
    private Output<String> modelId;

    public Output<String> modelId() {
        return this.modelId;
    }
    @Export(name="namespace", refs={String.class}, tree="[0]")
    private Output<String> namespace;

    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public ModelArtifactImport(java.lang.String name) {
        this(name, ModelArtifactImportArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public ModelArtifactImport(java.lang.String name, ModelArtifactImportArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public ModelArtifactImport(java.lang.String name, ModelArtifactImportArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataScience/modelArtifactImport:ModelArtifactImport", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private ModelArtifactImport(java.lang.String name, Output<java.lang.String> id, @Nullable ModelArtifactImportState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataScience/modelArtifactImport:ModelArtifactImport", name, state, makeResourceOptions(options, id), false);
    }

    private static ModelArtifactImportArgs makeArgs(ModelArtifactImportArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? ModelArtifactImportArgs.Empty : args;
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
    public static ModelArtifactImport get(java.lang.String name, Output<java.lang.String> id, @Nullable ModelArtifactImportState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new ModelArtifactImport(name, id, state, options);
    }
}

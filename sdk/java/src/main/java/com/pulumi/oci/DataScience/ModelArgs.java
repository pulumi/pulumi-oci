// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.inputs.ModelBackupSettingArgs;
import com.pulumi.oci.DataScience.inputs.ModelCustomMetadataListArgs;
import com.pulumi.oci.DataScience.inputs.ModelDefinedMetadataListArgs;
import com.pulumi.oci.DataScience.inputs.ModelRetentionSettingArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelArgs Empty = new ModelArgs();

    /**
     * This allows to specify a filename during upload. This file name is used to dispose of the file contents while downloading the file. Example: `attachment; filename=model-artifact.zip`
     * 
     */
    @Import(name="artifactContentDisposition")
    private @Nullable Output<String> artifactContentDisposition;

    /**
     * @return This allows to specify a filename during upload. This file name is used to dispose of the file contents while downloading the file. Example: `attachment; filename=model-artifact.zip`
     * 
     */
    public Optional<Output<String>> artifactContentDisposition() {
        return Optional.ofNullable(this.artifactContentDisposition);
    }

    /**
     * The content length of the model_artifact.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="artifactContentLength", required=true)
    private Output<String> artifactContentLength;

    /**
     * @return The content length of the model_artifact.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> artifactContentLength() {
        return this.artifactContentLength;
    }

    /**
     * (Updatable) Back up setting details of the model.
     * 
     */
    @Import(name="backupSetting")
    private @Nullable Output<ModelBackupSettingArgs> backupSetting;

    /**
     * @return (Updatable) Back up setting details of the model.
     * 
     */
    public Optional<Output<ModelBackupSettingArgs>> backupSetting() {
        return Optional.ofNullable(this.backupSetting);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model in.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model in.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) An array of custom metadata details for the model.
     * 
     */
    @Import(name="customMetadataLists")
    private @Nullable Output<List<ModelCustomMetadataListArgs>> customMetadataLists;

    /**
     * @return (Updatable) An array of custom metadata details for the model.
     * 
     */
    public Optional<Output<List<ModelCustomMetadataListArgs>>> customMetadataLists() {
        return Optional.ofNullable(this.customMetadataLists);
    }

    /**
     * (Updatable) An array of defined metadata details for the model.
     * 
     */
    @Import(name="definedMetadataLists")
    private @Nullable Output<List<ModelDefinedMetadataListArgs>> definedMetadataLists;

    /**
     * @return (Updatable) An array of defined metadata details for the model.
     * 
     */
    public Optional<Output<List<ModelDefinedMetadataListArgs>>> definedMetadataLists() {
        return Optional.ofNullable(this.definedMetadataLists);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A short description of the model.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A short description of the model.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My Model`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My Model`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Input schema file content in String format
     * 
     */
    @Import(name="inputSchema")
    private @Nullable Output<String> inputSchema;

    /**
     * @return Input schema file content in String format
     * 
     */
    public Optional<Output<String>> inputSchema() {
        return Optional.ofNullable(this.inputSchema);
    }

    /**
     * The model artifact to upload. It is a ZIP archive of the files necessary to run the model. This can be done in a separate step or using cli/sdk. The Model will remain in &#34;Creating&#34; state until its artifact is uploaded.
     * 
     */
    @Import(name="modelArtifact", required=true)
    private Output<String> modelArtifact;

    /**
     * @return The model artifact to upload. It is a ZIP archive of the files necessary to run the model. This can be done in a separate step or using cli/sdk. The Model will remain in &#34;Creating&#34; state until its artifact is uploaded.
     * 
     */
    public Output<String> modelArtifact() {
        return this.modelArtifact;
    }

    /**
     * The OCID of the model version set that the model is associated to.
     * 
     */
    @Import(name="modelVersionSetId")
    private @Nullable Output<String> modelVersionSetId;

    /**
     * @return The OCID of the model version set that the model is associated to.
     * 
     */
    public Optional<Output<String>> modelVersionSetId() {
        return Optional.ofNullable(this.modelVersionSetId);
    }

    /**
     * The name of the model version set that the model is associated to.
     * 
     */
    @Import(name="modelVersionSetName")
    private @Nullable Output<String> modelVersionSetName;

    /**
     * @return The name of the model version set that the model is associated to.
     * 
     */
    public Optional<Output<String>> modelVersionSetName() {
        return Optional.ofNullable(this.modelVersionSetName);
    }

    /**
     * Output schema file content in String format
     * 
     */
    @Import(name="outputSchema")
    private @Nullable Output<String> outputSchema;

    /**
     * @return Output schema file content in String format
     * 
     */
    public Optional<Output<String>> outputSchema() {
        return Optional.ofNullable(this.outputSchema);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     * 
     */
    @Import(name="projectId", required=true)
    private Output<String> projectId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }

    /**
     * (Updatable) Retention setting details of the model.
     * 
     */
    @Import(name="retentionSetting")
    private @Nullable Output<ModelRetentionSettingArgs> retentionSetting;

    /**
     * @return (Updatable) Retention setting details of the model.
     * 
     */
    public Optional<Output<ModelRetentionSettingArgs>> retentionSetting() {
        return Optional.ofNullable(this.retentionSetting);
    }

    /**
     * The state of the model.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The state of the model.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * (Updatable) The version label can add an additional description of the lifecycle state of the model or the application using/training the model.
     * 
     */
    @Import(name="versionLabel")
    private @Nullable Output<String> versionLabel;

    /**
     * @return (Updatable) The version label can add an additional description of the lifecycle state of the model or the application using/training the model.
     * 
     */
    public Optional<Output<String>> versionLabel() {
        return Optional.ofNullable(this.versionLabel);
    }

    private ModelArgs() {}

    private ModelArgs(ModelArgs $) {
        this.artifactContentDisposition = $.artifactContentDisposition;
        this.artifactContentLength = $.artifactContentLength;
        this.backupSetting = $.backupSetting;
        this.compartmentId = $.compartmentId;
        this.customMetadataLists = $.customMetadataLists;
        this.definedMetadataLists = $.definedMetadataLists;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.inputSchema = $.inputSchema;
        this.modelArtifact = $.modelArtifact;
        this.modelVersionSetId = $.modelVersionSetId;
        this.modelVersionSetName = $.modelVersionSetName;
        this.outputSchema = $.outputSchema;
        this.projectId = $.projectId;
        this.retentionSetting = $.retentionSetting;
        this.state = $.state;
        this.versionLabel = $.versionLabel;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelArgs $;

        public Builder() {
            $ = new ModelArgs();
        }

        public Builder(ModelArgs defaults) {
            $ = new ModelArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param artifactContentDisposition This allows to specify a filename during upload. This file name is used to dispose of the file contents while downloading the file. Example: `attachment; filename=model-artifact.zip`
         * 
         * @return builder
         * 
         */
        public Builder artifactContentDisposition(@Nullable Output<String> artifactContentDisposition) {
            $.artifactContentDisposition = artifactContentDisposition;
            return this;
        }

        /**
         * @param artifactContentDisposition This allows to specify a filename during upload. This file name is used to dispose of the file contents while downloading the file. Example: `attachment; filename=model-artifact.zip`
         * 
         * @return builder
         * 
         */
        public Builder artifactContentDisposition(String artifactContentDisposition) {
            return artifactContentDisposition(Output.of(artifactContentDisposition));
        }

        /**
         * @param artifactContentLength The content length of the model_artifact.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder artifactContentLength(Output<String> artifactContentLength) {
            $.artifactContentLength = artifactContentLength;
            return this;
        }

        /**
         * @param artifactContentLength The content length of the model_artifact.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder artifactContentLength(String artifactContentLength) {
            return artifactContentLength(Output.of(artifactContentLength));
        }

        /**
         * @param backupSetting (Updatable) Back up setting details of the model.
         * 
         * @return builder
         * 
         */
        public Builder backupSetting(@Nullable Output<ModelBackupSettingArgs> backupSetting) {
            $.backupSetting = backupSetting;
            return this;
        }

        /**
         * @param backupSetting (Updatable) Back up setting details of the model.
         * 
         * @return builder
         * 
         */
        public Builder backupSetting(ModelBackupSettingArgs backupSetting) {
            return backupSetting(Output.of(backupSetting));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model in.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the model in.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param customMetadataLists (Updatable) An array of custom metadata details for the model.
         * 
         * @return builder
         * 
         */
        public Builder customMetadataLists(@Nullable Output<List<ModelCustomMetadataListArgs>> customMetadataLists) {
            $.customMetadataLists = customMetadataLists;
            return this;
        }

        /**
         * @param customMetadataLists (Updatable) An array of custom metadata details for the model.
         * 
         * @return builder
         * 
         */
        public Builder customMetadataLists(List<ModelCustomMetadataListArgs> customMetadataLists) {
            return customMetadataLists(Output.of(customMetadataLists));
        }

        /**
         * @param customMetadataLists (Updatable) An array of custom metadata details for the model.
         * 
         * @return builder
         * 
         */
        public Builder customMetadataLists(ModelCustomMetadataListArgs... customMetadataLists) {
            return customMetadataLists(List.of(customMetadataLists));
        }

        /**
         * @param definedMetadataLists (Updatable) An array of defined metadata details for the model.
         * 
         * @return builder
         * 
         */
        public Builder definedMetadataLists(@Nullable Output<List<ModelDefinedMetadataListArgs>> definedMetadataLists) {
            $.definedMetadataLists = definedMetadataLists;
            return this;
        }

        /**
         * @param definedMetadataLists (Updatable) An array of defined metadata details for the model.
         * 
         * @return builder
         * 
         */
        public Builder definedMetadataLists(List<ModelDefinedMetadataListArgs> definedMetadataLists) {
            return definedMetadataLists(Output.of(definedMetadataLists));
        }

        /**
         * @param definedMetadataLists (Updatable) An array of defined metadata details for the model.
         * 
         * @return builder
         * 
         */
        public Builder definedMetadataLists(ModelDefinedMetadataListArgs... definedMetadataLists) {
            return definedMetadataLists(List.of(definedMetadataLists));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A short description of the model.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A short description of the model.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My Model`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information. Example: `My Model`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param inputSchema Input schema file content in String format
         * 
         * @return builder
         * 
         */
        public Builder inputSchema(@Nullable Output<String> inputSchema) {
            $.inputSchema = inputSchema;
            return this;
        }

        /**
         * @param inputSchema Input schema file content in String format
         * 
         * @return builder
         * 
         */
        public Builder inputSchema(String inputSchema) {
            return inputSchema(Output.of(inputSchema));
        }

        /**
         * @param modelArtifact The model artifact to upload. It is a ZIP archive of the files necessary to run the model. This can be done in a separate step or using cli/sdk. The Model will remain in &#34;Creating&#34; state until its artifact is uploaded.
         * 
         * @return builder
         * 
         */
        public Builder modelArtifact(Output<String> modelArtifact) {
            $.modelArtifact = modelArtifact;
            return this;
        }

        /**
         * @param modelArtifact The model artifact to upload. It is a ZIP archive of the files necessary to run the model. This can be done in a separate step or using cli/sdk. The Model will remain in &#34;Creating&#34; state until its artifact is uploaded.
         * 
         * @return builder
         * 
         */
        public Builder modelArtifact(String modelArtifact) {
            return modelArtifact(Output.of(modelArtifact));
        }

        /**
         * @param modelVersionSetId The OCID of the model version set that the model is associated to.
         * 
         * @return builder
         * 
         */
        public Builder modelVersionSetId(@Nullable Output<String> modelVersionSetId) {
            $.modelVersionSetId = modelVersionSetId;
            return this;
        }

        /**
         * @param modelVersionSetId The OCID of the model version set that the model is associated to.
         * 
         * @return builder
         * 
         */
        public Builder modelVersionSetId(String modelVersionSetId) {
            return modelVersionSetId(Output.of(modelVersionSetId));
        }

        /**
         * @param modelVersionSetName The name of the model version set that the model is associated to.
         * 
         * @return builder
         * 
         */
        public Builder modelVersionSetName(@Nullable Output<String> modelVersionSetName) {
            $.modelVersionSetName = modelVersionSetName;
            return this;
        }

        /**
         * @param modelVersionSetName The name of the model version set that the model is associated to.
         * 
         * @return builder
         * 
         */
        public Builder modelVersionSetName(String modelVersionSetName) {
            return modelVersionSetName(Output.of(modelVersionSetName));
        }

        /**
         * @param outputSchema Output schema file content in String format
         * 
         * @return builder
         * 
         */
        public Builder outputSchema(@Nullable Output<String> outputSchema) {
            $.outputSchema = outputSchema;
            return this;
        }

        /**
         * @param outputSchema Output schema file content in String format
         * 
         * @return builder
         * 
         */
        public Builder outputSchema(String outputSchema) {
            return outputSchema(Output.of(outputSchema));
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
         * 
         * @return builder
         * 
         */
        public Builder projectId(Output<String> projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param projectId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the model.
         * 
         * @return builder
         * 
         */
        public Builder projectId(String projectId) {
            return projectId(Output.of(projectId));
        }

        /**
         * @param retentionSetting (Updatable) Retention setting details of the model.
         * 
         * @return builder
         * 
         */
        public Builder retentionSetting(@Nullable Output<ModelRetentionSettingArgs> retentionSetting) {
            $.retentionSetting = retentionSetting;
            return this;
        }

        /**
         * @param retentionSetting (Updatable) Retention setting details of the model.
         * 
         * @return builder
         * 
         */
        public Builder retentionSetting(ModelRetentionSettingArgs retentionSetting) {
            return retentionSetting(Output.of(retentionSetting));
        }

        /**
         * @param state The state of the model.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The state of the model.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param versionLabel (Updatable) The version label can add an additional description of the lifecycle state of the model or the application using/training the model.
         * 
         * @return builder
         * 
         */
        public Builder versionLabel(@Nullable Output<String> versionLabel) {
            $.versionLabel = versionLabel;
            return this;
        }

        /**
         * @param versionLabel (Updatable) The version label can add an additional description of the lifecycle state of the model or the application using/training the model.
         * 
         * @return builder
         * 
         */
        public Builder versionLabel(String versionLabel) {
            return versionLabel(Output.of(versionLabel));
        }

        public ModelArgs build() {
            if ($.artifactContentLength == null) {
                throw new MissingRequiredPropertyException("ModelArgs", "artifactContentLength");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("ModelArgs", "compartmentId");
            }
            if ($.modelArtifact == null) {
                throw new MissingRequiredPropertyException("ModelArgs", "modelArtifact");
            }
            if ($.projectId == null) {
                throw new MissingRequiredPropertyException("ModelArgs", "projectId");
            }
            return $;
        }
    }

}

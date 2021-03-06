// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataConnectivity.inputs.RegistryDataAssetNativeTypeSystemTypeConfigDefinitionParentRefArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs extends com.pulumi.resources.ResourceArgs {

    public static final RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs Empty = new RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs();

    /**
     * (Updatable) The parameter configuration details.
     * 
     */
    @Import(name="configParameterDefinitions")
    private @Nullable Output<Map<String,Object>> configParameterDefinitions;

    /**
     * @return (Updatable) The parameter configuration details.
     * 
     */
    public Optional<Output<Map<String,Object>>> configParameterDefinitions() {
        return Optional.ofNullable(this.configParameterDefinitions);
    }

    /**
     * (Updatable) Specifies whether the configuration is contained or not.
     * 
     */
    @Import(name="isContained")
    private @Nullable Output<Boolean> isContained;

    /**
     * @return (Updatable) Specifies whether the configuration is contained or not.
     * 
     */
    public Optional<Output<Boolean>> isContained() {
        return Optional.ofNullable(this.isContained);
    }

    /**
     * (Updatable) The identifying key for the object.
     * 
     */
    @Import(name="key")
    private @Nullable Output<String> key;

    /**
     * @return (Updatable) The identifying key for the object.
     * 
     */
    public Optional<Output<String>> key() {
        return Optional.ofNullable(this.key);
    }

    /**
     * (Updatable) The property which disciminates the subtypes.
     * 
     */
    @Import(name="modelType")
    private @Nullable Output<String> modelType;

    /**
     * @return (Updatable) The property which disciminates the subtypes.
     * 
     */
    public Optional<Output<String>> modelType() {
        return Optional.ofNullable(this.modelType);
    }

    /**
     * (Updatable) The model version of an object.
     * 
     */
    @Import(name="modelVersion")
    private @Nullable Output<String> modelVersion;

    /**
     * @return (Updatable) The model version of an object.
     * 
     */
    public Optional<Output<String>> modelVersion() {
        return Optional.ofNullable(this.modelVersion);
    }

    /**
     * (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    @Import(name="objectStatus")
    private @Nullable Output<Integer> objectStatus;

    /**
     * @return (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
     * 
     */
    public Optional<Output<Integer>> objectStatus() {
        return Optional.ofNullable(this.objectStatus);
    }

    /**
     * (Updatable) A reference to the object&#39;s parent.
     * 
     */
    @Import(name="parentRef")
    private @Nullable Output<RegistryDataAssetNativeTypeSystemTypeConfigDefinitionParentRefArgs> parentRef;

    /**
     * @return (Updatable) A reference to the object&#39;s parent.
     * 
     */
    public Optional<Output<RegistryDataAssetNativeTypeSystemTypeConfigDefinitionParentRefArgs>> parentRef() {
        return Optional.ofNullable(this.parentRef);
    }

    private RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs() {}

    private RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs(RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs $) {
        this.configParameterDefinitions = $.configParameterDefinitions;
        this.isContained = $.isContained;
        this.key = $.key;
        this.modelType = $.modelType;
        this.modelVersion = $.modelVersion;
        this.name = $.name;
        this.objectStatus = $.objectStatus;
        this.parentRef = $.parentRef;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs $;

        public Builder() {
            $ = new RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs();
        }

        public Builder(RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs defaults) {
            $ = new RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param configParameterDefinitions (Updatable) The parameter configuration details.
         * 
         * @return builder
         * 
         */
        public Builder configParameterDefinitions(@Nullable Output<Map<String,Object>> configParameterDefinitions) {
            $.configParameterDefinitions = configParameterDefinitions;
            return this;
        }

        /**
         * @param configParameterDefinitions (Updatable) The parameter configuration details.
         * 
         * @return builder
         * 
         */
        public Builder configParameterDefinitions(Map<String,Object> configParameterDefinitions) {
            return configParameterDefinitions(Output.of(configParameterDefinitions));
        }

        /**
         * @param isContained (Updatable) Specifies whether the configuration is contained or not.
         * 
         * @return builder
         * 
         */
        public Builder isContained(@Nullable Output<Boolean> isContained) {
            $.isContained = isContained;
            return this;
        }

        /**
         * @param isContained (Updatable) Specifies whether the configuration is contained or not.
         * 
         * @return builder
         * 
         */
        public Builder isContained(Boolean isContained) {
            return isContained(Output.of(isContained));
        }

        /**
         * @param key (Updatable) The identifying key for the object.
         * 
         * @return builder
         * 
         */
        public Builder key(@Nullable Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key (Updatable) The identifying key for the object.
         * 
         * @return builder
         * 
         */
        public Builder key(String key) {
            return key(Output.of(key));
        }

        /**
         * @param modelType (Updatable) The property which disciminates the subtypes.
         * 
         * @return builder
         * 
         */
        public Builder modelType(@Nullable Output<String> modelType) {
            $.modelType = modelType;
            return this;
        }

        /**
         * @param modelType (Updatable) The property which disciminates the subtypes.
         * 
         * @return builder
         * 
         */
        public Builder modelType(String modelType) {
            return modelType(Output.of(modelType));
        }

        /**
         * @param modelVersion (Updatable) The model version of an object.
         * 
         * @return builder
         * 
         */
        public Builder modelVersion(@Nullable Output<String> modelVersion) {
            $.modelVersion = modelVersion;
            return this;
        }

        /**
         * @param modelVersion (Updatable) The model version of an object.
         * 
         * @return builder
         * 
         */
        public Builder modelVersion(String modelVersion) {
            return modelVersion(Output.of(modelVersion));
        }

        /**
         * @param name (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param objectStatus (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
         * 
         * @return builder
         * 
         */
        public Builder objectStatus(@Nullable Output<Integer> objectStatus) {
            $.objectStatus = objectStatus;
            return this;
        }

        /**
         * @param objectStatus (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
         * 
         * @return builder
         * 
         */
        public Builder objectStatus(Integer objectStatus) {
            return objectStatus(Output.of(objectStatus));
        }

        /**
         * @param parentRef (Updatable) A reference to the object&#39;s parent.
         * 
         * @return builder
         * 
         */
        public Builder parentRef(@Nullable Output<RegistryDataAssetNativeTypeSystemTypeConfigDefinitionParentRefArgs> parentRef) {
            $.parentRef = parentRef;
            return this;
        }

        /**
         * @param parentRef (Updatable) A reference to the object&#39;s parent.
         * 
         * @return builder
         * 
         */
        public Builder parentRef(RegistryDataAssetNativeTypeSystemTypeConfigDefinitionParentRefArgs parentRef) {
            return parentRef(Output.of(parentRef));
        }

        public RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs build() {
            return $;
        }
    }

}

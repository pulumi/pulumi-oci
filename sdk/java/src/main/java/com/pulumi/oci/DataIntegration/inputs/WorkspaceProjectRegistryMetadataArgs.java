// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class WorkspaceProjectRegistryMetadataArgs extends com.pulumi.resources.ResourceArgs {

    public static final WorkspaceProjectRegistryMetadataArgs Empty = new WorkspaceProjectRegistryMetadataArgs();

    /**
     * (Updatable) The owning object&#39;s key for this object.
     * 
     */
    @Import(name="aggregatorKey")
    private @Nullable Output<String> aggregatorKey;

    /**
     * @return (Updatable) The owning object&#39;s key for this object.
     * 
     */
    public Optional<Output<String>> aggregatorKey() {
        return Optional.ofNullable(this.aggregatorKey);
    }

    /**
     * (Updatable) Specifies whether this object is a favorite or not.
     * 
     */
    @Import(name="isFavorite")
    private @Nullable Output<Boolean> isFavorite;

    /**
     * @return (Updatable) Specifies whether this object is a favorite or not.
     * 
     */
    public Optional<Output<Boolean>> isFavorite() {
        return Optional.ofNullable(this.isFavorite);
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
     * (Updatable) Labels are keywords or labels that you can add to data assets, dataflows etc. You can define your own labels and use them to categorize content.
     * 
     */
    @Import(name="labels")
    private @Nullable Output<List<String>> labels;

    /**
     * @return (Updatable) Labels are keywords or labels that you can add to data assets, dataflows etc. You can define your own labels and use them to categorize content.
     * 
     */
    public Optional<Output<List<String>>> labels() {
        return Optional.ofNullable(this.labels);
    }

    /**
     * (Updatable) The registry version.
     * 
     */
    @Import(name="registryVersion")
    private @Nullable Output<Integer> registryVersion;

    /**
     * @return (Updatable) The registry version.
     * 
     */
    public Optional<Output<Integer>> registryVersion() {
        return Optional.ofNullable(this.registryVersion);
    }

    private WorkspaceProjectRegistryMetadataArgs() {}

    private WorkspaceProjectRegistryMetadataArgs(WorkspaceProjectRegistryMetadataArgs $) {
        this.aggregatorKey = $.aggregatorKey;
        this.isFavorite = $.isFavorite;
        this.key = $.key;
        this.labels = $.labels;
        this.registryVersion = $.registryVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(WorkspaceProjectRegistryMetadataArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private WorkspaceProjectRegistryMetadataArgs $;

        public Builder() {
            $ = new WorkspaceProjectRegistryMetadataArgs();
        }

        public Builder(WorkspaceProjectRegistryMetadataArgs defaults) {
            $ = new WorkspaceProjectRegistryMetadataArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param aggregatorKey (Updatable) The owning object&#39;s key for this object.
         * 
         * @return builder
         * 
         */
        public Builder aggregatorKey(@Nullable Output<String> aggregatorKey) {
            $.aggregatorKey = aggregatorKey;
            return this;
        }

        /**
         * @param aggregatorKey (Updatable) The owning object&#39;s key for this object.
         * 
         * @return builder
         * 
         */
        public Builder aggregatorKey(String aggregatorKey) {
            return aggregatorKey(Output.of(aggregatorKey));
        }

        /**
         * @param isFavorite (Updatable) Specifies whether this object is a favorite or not.
         * 
         * @return builder
         * 
         */
        public Builder isFavorite(@Nullable Output<Boolean> isFavorite) {
            $.isFavorite = isFavorite;
            return this;
        }

        /**
         * @param isFavorite (Updatable) Specifies whether this object is a favorite or not.
         * 
         * @return builder
         * 
         */
        public Builder isFavorite(Boolean isFavorite) {
            return isFavorite(Output.of(isFavorite));
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
         * @param labels (Updatable) Labels are keywords or labels that you can add to data assets, dataflows etc. You can define your own labels and use them to categorize content.
         * 
         * @return builder
         * 
         */
        public Builder labels(@Nullable Output<List<String>> labels) {
            $.labels = labels;
            return this;
        }

        /**
         * @param labels (Updatable) Labels are keywords or labels that you can add to data assets, dataflows etc. You can define your own labels and use them to categorize content.
         * 
         * @return builder
         * 
         */
        public Builder labels(List<String> labels) {
            return labels(Output.of(labels));
        }

        /**
         * @param labels (Updatable) Labels are keywords or labels that you can add to data assets, dataflows etc. You can define your own labels and use them to categorize content.
         * 
         * @return builder
         * 
         */
        public Builder labels(String... labels) {
            return labels(List.of(labels));
        }

        /**
         * @param registryVersion (Updatable) The registry version.
         * 
         * @return builder
         * 
         */
        public Builder registryVersion(@Nullable Output<Integer> registryVersion) {
            $.registryVersion = registryVersion;
            return this;
        }

        /**
         * @param registryVersion (Updatable) The registry version.
         * 
         * @return builder
         * 
         */
        public Builder registryVersion(Integer registryVersion) {
            return registryVersion(Output.of(registryVersion));
        }

        public WorkspaceProjectRegistryMetadataArgs build() {
            return $;
        }
    }

}
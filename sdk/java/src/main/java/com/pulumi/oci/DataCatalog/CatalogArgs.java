// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataCatalog;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CatalogArgs extends com.pulumi.resources.ResourceArgs {

    public static final CatalogArgs Empty = new CatalogArgs();

    /**
     * (Updatable) The list of private reverse connection endpoints attached to the catalog
     * 
     */
    @Import(name="attachedCatalogPrivateEndpoints")
    private @Nullable Output<List<String>> attachedCatalogPrivateEndpoints;

    /**
     * @return (Updatable) The list of private reverse connection endpoints attached to the catalog
     * 
     */
    public Optional<Output<List<String>>> attachedCatalogPrivateEndpoints() {
        return Optional.ofNullable(this.attachedCatalogPrivateEndpoints);
    }

    /**
     * (Updatable) Compartment identifier.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment identifier.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Data catalog identifier.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Data catalog identifier.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    private CatalogArgs() {}

    private CatalogArgs(CatalogArgs $) {
        this.attachedCatalogPrivateEndpoints = $.attachedCatalogPrivateEndpoints;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CatalogArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CatalogArgs $;

        public Builder() {
            $ = new CatalogArgs();
        }

        public Builder(CatalogArgs defaults) {
            $ = new CatalogArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param attachedCatalogPrivateEndpoints (Updatable) The list of private reverse connection endpoints attached to the catalog
         * 
         * @return builder
         * 
         */
        public Builder attachedCatalogPrivateEndpoints(@Nullable Output<List<String>> attachedCatalogPrivateEndpoints) {
            $.attachedCatalogPrivateEndpoints = attachedCatalogPrivateEndpoints;
            return this;
        }

        /**
         * @param attachedCatalogPrivateEndpoints (Updatable) The list of private reverse connection endpoints attached to the catalog
         * 
         * @return builder
         * 
         */
        public Builder attachedCatalogPrivateEndpoints(List<String> attachedCatalogPrivateEndpoints) {
            return attachedCatalogPrivateEndpoints(Output.of(attachedCatalogPrivateEndpoints));
        }

        /**
         * @param attachedCatalogPrivateEndpoints (Updatable) The list of private reverse connection endpoints attached to the catalog
         * 
         * @return builder
         * 
         */
        public Builder attachedCatalogPrivateEndpoints(String... attachedCatalogPrivateEndpoints) {
            return attachedCatalogPrivateEndpoints(List.of(attachedCatalogPrivateEndpoints));
        }

        /**
         * @param compartmentId (Updatable) Compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Data catalog identifier.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Data catalog identifier.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        public CatalogArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}
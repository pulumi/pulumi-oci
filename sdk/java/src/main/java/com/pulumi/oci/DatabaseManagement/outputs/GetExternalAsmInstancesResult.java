// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalAsmInstancesExternalAsmInstanceCollection;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalAsmInstancesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetExternalAsmInstancesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return The user-friendly name for the ASM instance. The name does not have to be unique.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM that the ASM instance belongs to.
     * 
     */
    private @Nullable String externalAsmId;
    /**
     * @return The list of external_asm_instance_collection.
     * 
     */
    private List<GetExternalAsmInstancesExternalAsmInstanceCollection> externalAsmInstanceCollections;
    private @Nullable List<GetExternalAsmInstancesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetExternalAsmInstancesResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The user-friendly name for the ASM instance. The name does not have to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM that the ASM instance belongs to.
     * 
     */
    public Optional<String> externalAsmId() {
        return Optional.ofNullable(this.externalAsmId);
    }
    /**
     * @return The list of external_asm_instance_collection.
     * 
     */
    public List<GetExternalAsmInstancesExternalAsmInstanceCollection> externalAsmInstanceCollections() {
        return this.externalAsmInstanceCollections;
    }
    public List<GetExternalAsmInstancesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalAsmInstancesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String displayName;
        private @Nullable String externalAsmId;
        private List<GetExternalAsmInstancesExternalAsmInstanceCollection> externalAsmInstanceCollections;
        private @Nullable List<GetExternalAsmInstancesFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetExternalAsmInstancesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.externalAsmId = defaults.externalAsmId;
    	      this.externalAsmInstanceCollections = defaults.externalAsmInstanceCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder externalAsmId(@Nullable String externalAsmId) {
            this.externalAsmId = externalAsmId;
            return this;
        }
        @CustomType.Setter
        public Builder externalAsmInstanceCollections(List<GetExternalAsmInstancesExternalAsmInstanceCollection> externalAsmInstanceCollections) {
            this.externalAsmInstanceCollections = Objects.requireNonNull(externalAsmInstanceCollections);
            return this;
        }
        public Builder externalAsmInstanceCollections(GetExternalAsmInstancesExternalAsmInstanceCollection... externalAsmInstanceCollections) {
            return externalAsmInstanceCollections(List.of(externalAsmInstanceCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetExternalAsmInstancesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetExternalAsmInstancesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetExternalAsmInstancesResult build() {
            final var o = new GetExternalAsmInstancesResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.externalAsmId = externalAsmId;
            o.externalAsmInstanceCollections = externalAsmInstanceCollections;
            o.filters = filters;
            o.id = id;
            return o;
        }
    }
}
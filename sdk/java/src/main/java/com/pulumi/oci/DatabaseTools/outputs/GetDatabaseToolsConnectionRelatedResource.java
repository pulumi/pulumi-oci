// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDatabaseToolsConnectionRelatedResource {
    /**
     * @return The resource entity type.
     * 
     */
    private String entityType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
     * 
     */
    private String identifier;

    private GetDatabaseToolsConnectionRelatedResource() {}
    /**
     * @return The resource entity type.
     * 
     */
    public String entityType() {
        return this.entityType;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
     * 
     */
    public String identifier() {
        return this.identifier;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseToolsConnectionRelatedResource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String entityType;
        private String identifier;
        public Builder() {}
        public Builder(GetDatabaseToolsConnectionRelatedResource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.entityType = defaults.entityType;
    	      this.identifier = defaults.identifier;
        }

        @CustomType.Setter
        public Builder entityType(String entityType) {
            this.entityType = Objects.requireNonNull(entityType);
            return this;
        }
        @CustomType.Setter
        public Builder identifier(String identifier) {
            this.identifier = Objects.requireNonNull(identifier);
            return this;
        }
        public GetDatabaseToolsConnectionRelatedResource build() {
            final var o = new GetDatabaseToolsConnectionRelatedResource();
            o.entityType = entityType;
            o.identifier = identifier;
            return o;
        }
    }
}
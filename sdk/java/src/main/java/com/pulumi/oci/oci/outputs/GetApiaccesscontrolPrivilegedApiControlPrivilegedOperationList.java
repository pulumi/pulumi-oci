// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetApiaccesscontrolPrivilegedApiControlPrivilegedOperationList {
    /**
     * @return name of the api which needs to be protected.
     * 
     */
    private String apiName;
    /**
     * @return list of attributes belonging to the above api which needs to be protected.
     * 
     */
    private List<String> attributeNames;
    /**
     * @return type of the entity which needs to be protected.
     * 
     */
    private String entityType;

    private GetApiaccesscontrolPrivilegedApiControlPrivilegedOperationList() {}
    /**
     * @return name of the api which needs to be protected.
     * 
     */
    public String apiName() {
        return this.apiName;
    }
    /**
     * @return list of attributes belonging to the above api which needs to be protected.
     * 
     */
    public List<String> attributeNames() {
        return this.attributeNames;
    }
    /**
     * @return type of the entity which needs to be protected.
     * 
     */
    public String entityType() {
        return this.entityType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiaccesscontrolPrivilegedApiControlPrivilegedOperationList defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apiName;
        private List<String> attributeNames;
        private String entityType;
        public Builder() {}
        public Builder(GetApiaccesscontrolPrivilegedApiControlPrivilegedOperationList defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apiName = defaults.apiName;
    	      this.attributeNames = defaults.attributeNames;
    	      this.entityType = defaults.entityType;
        }

        @CustomType.Setter
        public Builder apiName(String apiName) {
            if (apiName == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolPrivilegedApiControlPrivilegedOperationList", "apiName");
            }
            this.apiName = apiName;
            return this;
        }
        @CustomType.Setter
        public Builder attributeNames(List<String> attributeNames) {
            if (attributeNames == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolPrivilegedApiControlPrivilegedOperationList", "attributeNames");
            }
            this.attributeNames = attributeNames;
            return this;
        }
        public Builder attributeNames(String... attributeNames) {
            return attributeNames(List.of(attributeNames));
        }
        @CustomType.Setter
        public Builder entityType(String entityType) {
            if (entityType == null) {
              throw new MissingRequiredPropertyException("GetApiaccesscontrolPrivilegedApiControlPrivilegedOperationList", "entityType");
            }
            this.entityType = entityType;
            return this;
        }
        public GetApiaccesscontrolPrivilegedApiControlPrivilegedOperationList build() {
            final var _resultValue = new GetApiaccesscontrolPrivilegedApiControlPrivilegedOperationList();
            _resultValue.apiName = apiName;
            _resultValue.attributeNames = attributeNames;
            _resultValue.entityType = entityType;
            return _resultValue;
        }
    }
}

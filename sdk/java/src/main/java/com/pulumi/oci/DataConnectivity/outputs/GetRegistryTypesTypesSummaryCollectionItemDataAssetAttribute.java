// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRegistryTypesTypesSummaryCollectionItemDataAssetAttribute {
    /**
     * @return The attribute type details.
     * 
     */
    private String attributeType;
    /**
     * @return True if attribute is encoded.
     * 
     */
    private Boolean isBase64encoded;
    /**
     * @return True if attribute is generated.
     * 
     */
    private Boolean isGenerated;
    /**
     * @return True if attribute is mandatory.
     * 
     */
    private Boolean isMandatory;
    /**
     * @return True if attribute is sensitive.
     * 
     */
    private Boolean isSensitive;
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    private String name;
    /**
     * @return The list of valid keys.
     * 
     */
    private List<String> validKeyLists;

    private GetRegistryTypesTypesSummaryCollectionItemDataAssetAttribute() {}
    /**
     * @return The attribute type details.
     * 
     */
    public String attributeType() {
        return this.attributeType;
    }
    /**
     * @return True if attribute is encoded.
     * 
     */
    public Boolean isBase64encoded() {
        return this.isBase64encoded;
    }
    /**
     * @return True if attribute is generated.
     * 
     */
    public Boolean isGenerated() {
        return this.isGenerated;
    }
    /**
     * @return True if attribute is mandatory.
     * 
     */
    public Boolean isMandatory() {
        return this.isMandatory;
    }
    /**
     * @return True if attribute is sensitive.
     * 
     */
    public Boolean isSensitive() {
        return this.isSensitive;
    }
    /**
     * @return Used to filter by the name of the object.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The list of valid keys.
     * 
     */
    public List<String> validKeyLists() {
        return this.validKeyLists;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRegistryTypesTypesSummaryCollectionItemDataAssetAttribute defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String attributeType;
        private Boolean isBase64encoded;
        private Boolean isGenerated;
        private Boolean isMandatory;
        private Boolean isSensitive;
        private String name;
        private List<String> validKeyLists;
        public Builder() {}
        public Builder(GetRegistryTypesTypesSummaryCollectionItemDataAssetAttribute defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attributeType = defaults.attributeType;
    	      this.isBase64encoded = defaults.isBase64encoded;
    	      this.isGenerated = defaults.isGenerated;
    	      this.isMandatory = defaults.isMandatory;
    	      this.isSensitive = defaults.isSensitive;
    	      this.name = defaults.name;
    	      this.validKeyLists = defaults.validKeyLists;
        }

        @CustomType.Setter
        public Builder attributeType(String attributeType) {
            this.attributeType = Objects.requireNonNull(attributeType);
            return this;
        }
        @CustomType.Setter
        public Builder isBase64encoded(Boolean isBase64encoded) {
            this.isBase64encoded = Objects.requireNonNull(isBase64encoded);
            return this;
        }
        @CustomType.Setter
        public Builder isGenerated(Boolean isGenerated) {
            this.isGenerated = Objects.requireNonNull(isGenerated);
            return this;
        }
        @CustomType.Setter
        public Builder isMandatory(Boolean isMandatory) {
            this.isMandatory = Objects.requireNonNull(isMandatory);
            return this;
        }
        @CustomType.Setter
        public Builder isSensitive(Boolean isSensitive) {
            this.isSensitive = Objects.requireNonNull(isSensitive);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder validKeyLists(List<String> validKeyLists) {
            this.validKeyLists = Objects.requireNonNull(validKeyLists);
            return this;
        }
        public Builder validKeyLists(String... validKeyLists) {
            return validKeyLists(List.of(validKeyLists));
        }
        public GetRegistryTypesTypesSummaryCollectionItemDataAssetAttribute build() {
            final var o = new GetRegistryTypesTypesSummaryCollectionItemDataAssetAttribute();
            o.attributeType = attributeType;
            o.isBase64encoded = isBase64encoded;
            o.isGenerated = isGenerated;
            o.isMandatory = isMandatory;
            o.isSensitive = isSensitive;
            o.name = name;
            o.validKeyLists = validKeyLists;
            return o;
        }
    }
}
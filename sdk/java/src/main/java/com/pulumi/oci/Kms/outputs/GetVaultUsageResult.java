// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVaultUsageResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The number of keys in this vault, across all compartments, excluding keys in a `DELETED` state.
     * 
     */
    private Integer keyCount;
    /**
     * @return The number of key versions in this vault, across all compartments, excluding key versions in a `DELETED` state.
     * 
     */
    private Integer keyVersionCount;
    /**
     * @return The number of keys in this vault that persist on the server, across all compartments, excluding keys in a `DELETED` state.
     * 
     */
    private Integer softwareKeyCount;
    /**
     * @return The number of key versions in this vault that persist on the server, across all compartments, excluding key versions in a `DELETED` state.
     * 
     */
    private Integer softwareKeyVersionCount;
    private String vaultId;

    private GetVaultUsageResult() {}
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The number of keys in this vault, across all compartments, excluding keys in a `DELETED` state.
     * 
     */
    public Integer keyCount() {
        return this.keyCount;
    }
    /**
     * @return The number of key versions in this vault, across all compartments, excluding key versions in a `DELETED` state.
     * 
     */
    public Integer keyVersionCount() {
        return this.keyVersionCount;
    }
    /**
     * @return The number of keys in this vault that persist on the server, across all compartments, excluding keys in a `DELETED` state.
     * 
     */
    public Integer softwareKeyCount() {
        return this.softwareKeyCount;
    }
    /**
     * @return The number of key versions in this vault that persist on the server, across all compartments, excluding key versions in a `DELETED` state.
     * 
     */
    public Integer softwareKeyVersionCount() {
        return this.softwareKeyVersionCount;
    }
    public String vaultId() {
        return this.vaultId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVaultUsageResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private Integer keyCount;
        private Integer keyVersionCount;
        private Integer softwareKeyCount;
        private Integer softwareKeyVersionCount;
        private String vaultId;
        public Builder() {}
        public Builder(GetVaultUsageResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.keyCount = defaults.keyCount;
    	      this.keyVersionCount = defaults.keyVersionCount;
    	      this.softwareKeyCount = defaults.softwareKeyCount;
    	      this.softwareKeyVersionCount = defaults.softwareKeyVersionCount;
    	      this.vaultId = defaults.vaultId;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetVaultUsageResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder keyCount(Integer keyCount) {
            if (keyCount == null) {
              throw new MissingRequiredPropertyException("GetVaultUsageResult", "keyCount");
            }
            this.keyCount = keyCount;
            return this;
        }
        @CustomType.Setter
        public Builder keyVersionCount(Integer keyVersionCount) {
            if (keyVersionCount == null) {
              throw new MissingRequiredPropertyException("GetVaultUsageResult", "keyVersionCount");
            }
            this.keyVersionCount = keyVersionCount;
            return this;
        }
        @CustomType.Setter
        public Builder softwareKeyCount(Integer softwareKeyCount) {
            if (softwareKeyCount == null) {
              throw new MissingRequiredPropertyException("GetVaultUsageResult", "softwareKeyCount");
            }
            this.softwareKeyCount = softwareKeyCount;
            return this;
        }
        @CustomType.Setter
        public Builder softwareKeyVersionCount(Integer softwareKeyVersionCount) {
            if (softwareKeyVersionCount == null) {
              throw new MissingRequiredPropertyException("GetVaultUsageResult", "softwareKeyVersionCount");
            }
            this.softwareKeyVersionCount = softwareKeyVersionCount;
            return this;
        }
        @CustomType.Setter
        public Builder vaultId(String vaultId) {
            if (vaultId == null) {
              throw new MissingRequiredPropertyException("GetVaultUsageResult", "vaultId");
            }
            this.vaultId = vaultId;
            return this;
        }
        public GetVaultUsageResult build() {
            final var _resultValue = new GetVaultUsageResult();
            _resultValue.id = id;
            _resultValue.keyCount = keyCount;
            _resultValue.keyVersionCount = keyVersionCount;
            _resultValue.softwareKeyCount = softwareKeyCount;
            _resultValue.softwareKeyVersionCount = softwareKeyVersionCount;
            _resultValue.vaultId = vaultId;
            return _resultValue;
        }
    }
}

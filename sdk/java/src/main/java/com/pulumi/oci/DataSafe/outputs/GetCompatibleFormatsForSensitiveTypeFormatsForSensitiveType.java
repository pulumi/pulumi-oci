// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeMaskingFormat;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType {
    /**
     * @return An array of the library masking formats compatible with the sensitive type.
     * 
     */
    private final List<GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeMaskingFormat> maskingFormats;
    /**
     * @return The OCID of the sensitive type.
     * 
     */
    private final String sensitiveTypeId;

    @CustomType.Constructor
    private GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType(
        @CustomType.Parameter("maskingFormats") List<GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeMaskingFormat> maskingFormats,
        @CustomType.Parameter("sensitiveTypeId") String sensitiveTypeId) {
        this.maskingFormats = maskingFormats;
        this.sensitiveTypeId = sensitiveTypeId;
    }

    /**
     * @return An array of the library masking formats compatible with the sensitive type.
     * 
     */
    public List<GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeMaskingFormat> maskingFormats() {
        return this.maskingFormats;
    }
    /**
     * @return The OCID of the sensitive type.
     * 
     */
    public String sensitiveTypeId() {
        return this.sensitiveTypeId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeMaskingFormat> maskingFormats;
        private String sensitiveTypeId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.maskingFormats = defaults.maskingFormats;
    	      this.sensitiveTypeId = defaults.sensitiveTypeId;
        }

        public Builder maskingFormats(List<GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeMaskingFormat> maskingFormats) {
            this.maskingFormats = Objects.requireNonNull(maskingFormats);
            return this;
        }
        public Builder maskingFormats(GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveTypeMaskingFormat... maskingFormats) {
            return maskingFormats(List.of(maskingFormats));
        }
        public Builder sensitiveTypeId(String sensitiveTypeId) {
            this.sensitiveTypeId = Objects.requireNonNull(sensitiveTypeId);
            return this;
        }        public GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType build() {
            return new GetCompatibleFormatsForSensitiveTypeFormatsForSensitiveType(maskingFormats, sensitiveTypeId);
        }
    }
}

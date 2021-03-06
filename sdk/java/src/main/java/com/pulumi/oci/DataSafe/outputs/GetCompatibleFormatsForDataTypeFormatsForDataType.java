// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetCompatibleFormatsForDataTypeFormatsForDataTypeMaskingFormat;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCompatibleFormatsForDataTypeFormatsForDataType {
    /**
     * @return The data type category, which can be one of the following - Character - Includes CHAR, NCHAR, VARCHAR2, and NVARCHAR2 Numeric - Includes NUMBER, FLOAT, RAW, BINARY_FLOAT, and BINARY_DOUBLE Date - Includes DATE and TIMESTAMP LOB - Includes BLOB, CLOB, and NCLOB All - Includes all the supported data types
     * 
     */
    private final String dataType;
    /**
     * @return An array of the basic masking formats compatible with the data type category.
     * 
     */
    private final List<GetCompatibleFormatsForDataTypeFormatsForDataTypeMaskingFormat> maskingFormats;

    @CustomType.Constructor
    private GetCompatibleFormatsForDataTypeFormatsForDataType(
        @CustomType.Parameter("dataType") String dataType,
        @CustomType.Parameter("maskingFormats") List<GetCompatibleFormatsForDataTypeFormatsForDataTypeMaskingFormat> maskingFormats) {
        this.dataType = dataType;
        this.maskingFormats = maskingFormats;
    }

    /**
     * @return The data type category, which can be one of the following - Character - Includes CHAR, NCHAR, VARCHAR2, and NVARCHAR2 Numeric - Includes NUMBER, FLOAT, RAW, BINARY_FLOAT, and BINARY_DOUBLE Date - Includes DATE and TIMESTAMP LOB - Includes BLOB, CLOB, and NCLOB All - Includes all the supported data types
     * 
     */
    public String dataType() {
        return this.dataType;
    }
    /**
     * @return An array of the basic masking formats compatible with the data type category.
     * 
     */
    public List<GetCompatibleFormatsForDataTypeFormatsForDataTypeMaskingFormat> maskingFormats() {
        return this.maskingFormats;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCompatibleFormatsForDataTypeFormatsForDataType defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String dataType;
        private List<GetCompatibleFormatsForDataTypeFormatsForDataTypeMaskingFormat> maskingFormats;

        public Builder() {
    	      // Empty
        }

        public Builder(GetCompatibleFormatsForDataTypeFormatsForDataType defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dataType = defaults.dataType;
    	      this.maskingFormats = defaults.maskingFormats;
        }

        public Builder dataType(String dataType) {
            this.dataType = Objects.requireNonNull(dataType);
            return this;
        }
        public Builder maskingFormats(List<GetCompatibleFormatsForDataTypeFormatsForDataTypeMaskingFormat> maskingFormats) {
            this.maskingFormats = Objects.requireNonNull(maskingFormats);
            return this;
        }
        public Builder maskingFormats(GetCompatibleFormatsForDataTypeFormatsForDataTypeMaskingFormat... maskingFormats) {
            return maskingFormats(List.of(maskingFormats));
        }        public GetCompatibleFormatsForDataTypeFormatsForDataType build() {
            return new GetCompatibleFormatsForDataTypeFormatsForDataType(dataType, maskingFormats);
        }
    }
}

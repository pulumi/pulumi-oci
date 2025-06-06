// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmTraces.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTraceSpanTag {
    /**
     * @return Key that specifies the tag name.
     * 
     */
    private String tagName;
    /**
     * @return Value associated with the tag key.
     * 
     */
    private String tagValue;

    private GetTraceSpanTag() {}
    /**
     * @return Key that specifies the tag name.
     * 
     */
    public String tagName() {
        return this.tagName;
    }
    /**
     * @return Value associated with the tag key.
     * 
     */
    public String tagValue() {
        return this.tagValue;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTraceSpanTag defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String tagName;
        private String tagValue;
        public Builder() {}
        public Builder(GetTraceSpanTag defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.tagName = defaults.tagName;
    	      this.tagValue = defaults.tagValue;
        }

        @CustomType.Setter
        public Builder tagName(String tagName) {
            if (tagName == null) {
              throw new MissingRequiredPropertyException("GetTraceSpanTag", "tagName");
            }
            this.tagName = tagName;
            return this;
        }
        @CustomType.Setter
        public Builder tagValue(String tagValue) {
            if (tagValue == null) {
              throw new MissingRequiredPropertyException("GetTraceSpanTag", "tagValue");
            }
            this.tagValue = tagValue;
            return this;
        }
        public GetTraceSpanTag build() {
            final var _resultValue = new GetTraceSpanTag();
            _resultValue.tagName = tagName;
            _resultValue.tagValue = tagValue;
            return _resultValue;
        }
    }
}

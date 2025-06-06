// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam {
    /**
     * @return Contains macro parameter&#39;s names.
     * 
     */
    private String keyField;
    /**
     * @return Contains macro parameter&#39;s value.
     * 
     */
    private String valueField;

    private GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam() {}
    /**
     * @return Contains macro parameter&#39;s names.
     * 
     */
    public String keyField() {
        return this.keyField;
    }
    /**
     * @return Contains macro parameter&#39;s value.
     * 
     */
    public String valueField() {
        return this.valueField;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String keyField;
        private String valueField;
        public Builder() {}
        public Builder(GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.keyField = defaults.keyField;
    	      this.valueField = defaults.valueField;
        }

        @CustomType.Setter
        public Builder keyField(String keyField) {
            if (keyField == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam", "keyField");
            }
            this.keyField = keyField;
            return this;
        }
        @CustomType.Setter
        public Builder valueField(String valueField) {
            if (valueField == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam", "valueField");
            }
            this.valueField = valueField;
            return this;
        }
        public GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam build() {
            final var _resultValue = new GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam();
            _resultValue.keyField = keyField;
            _resultValue.valueField = valueField;
            return _resultValue;
        }
    }
}

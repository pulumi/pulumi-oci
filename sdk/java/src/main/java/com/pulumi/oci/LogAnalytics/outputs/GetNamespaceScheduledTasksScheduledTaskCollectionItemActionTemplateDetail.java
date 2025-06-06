// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.LogAnalytics.outputs.GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetail {
    /**
     * @return A filter to return only scheduled tasks whose stream action templateId matches the given id  exactly.
     * 
     */
    private String templateId;
    /**
     * @return To store macro params.
     * 
     */
    private List<GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam> templateParams;

    private GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetail() {}
    /**
     * @return A filter to return only scheduled tasks whose stream action templateId matches the given id  exactly.
     * 
     */
    public String templateId() {
        return this.templateId;
    }
    /**
     * @return To store macro params.
     * 
     */
    public List<GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam> templateParams() {
        return this.templateParams;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String templateId;
        private List<GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam> templateParams;
        public Builder() {}
        public Builder(GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.templateId = defaults.templateId;
    	      this.templateParams = defaults.templateParams;
        }

        @CustomType.Setter
        public Builder templateId(String templateId) {
            if (templateId == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetail", "templateId");
            }
            this.templateId = templateId;
            return this;
        }
        @CustomType.Setter
        public Builder templateParams(List<GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam> templateParams) {
            if (templateParams == null) {
              throw new MissingRequiredPropertyException("GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetail", "templateParams");
            }
            this.templateParams = templateParams;
            return this;
        }
        public Builder templateParams(GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetailTemplateParam... templateParams) {
            return templateParams(List.of(templateParams));
        }
        public GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetail build() {
            final var _resultValue = new GetNamespaceScheduledTasksScheduledTaskCollectionItemActionTemplateDetail();
            _resultValue.templateId = templateId;
            _resultValue.templateParams = templateParams;
            return _resultValue;
        }
    }
}

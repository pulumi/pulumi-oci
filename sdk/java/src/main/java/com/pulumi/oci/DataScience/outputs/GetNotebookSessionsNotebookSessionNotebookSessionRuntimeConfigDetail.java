// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataScience.outputs.GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetailNotebookSessionGitConfigDetail;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetail {
    /**
     * @return Custom environment variables for Notebook Session. These key-value pairs will be available for customers in Notebook Sessions.
     * 
     */
    private Map<String,Object> customEnvironmentVariables;
    /**
     * @return Git configuration Details.
     * 
     */
    private List<GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetailNotebookSessionGitConfigDetail> notebookSessionGitConfigDetails;

    private GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetail() {}
    /**
     * @return Custom environment variables for Notebook Session. These key-value pairs will be available for customers in Notebook Sessions.
     * 
     */
    public Map<String,Object> customEnvironmentVariables() {
        return this.customEnvironmentVariables;
    }
    /**
     * @return Git configuration Details.
     * 
     */
    public List<GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetailNotebookSessionGitConfigDetail> notebookSessionGitConfigDetails() {
        return this.notebookSessionGitConfigDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Map<String,Object> customEnvironmentVariables;
        private List<GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetailNotebookSessionGitConfigDetail> notebookSessionGitConfigDetails;
        public Builder() {}
        public Builder(GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.customEnvironmentVariables = defaults.customEnvironmentVariables;
    	      this.notebookSessionGitConfigDetails = defaults.notebookSessionGitConfigDetails;
        }

        @CustomType.Setter
        public Builder customEnvironmentVariables(Map<String,Object> customEnvironmentVariables) {
            this.customEnvironmentVariables = Objects.requireNonNull(customEnvironmentVariables);
            return this;
        }
        @CustomType.Setter
        public Builder notebookSessionGitConfigDetails(List<GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetailNotebookSessionGitConfigDetail> notebookSessionGitConfigDetails) {
            this.notebookSessionGitConfigDetails = Objects.requireNonNull(notebookSessionGitConfigDetails);
            return this;
        }
        public Builder notebookSessionGitConfigDetails(GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetailNotebookSessionGitConfigDetail... notebookSessionGitConfigDetails) {
            return notebookSessionGitConfigDetails(List.of(notebookSessionGitConfigDetails));
        }
        public GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetail build() {
            final var o = new GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetail();
            o.customEnvironmentVariables = customEnvironmentVariables;
            o.notebookSessionGitConfigDetails = notebookSessionGitConfigDetails;
            return o;
        }
    }
}
// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Adm.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetKnowledgebasePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetKnowledgebasePlainArgs Empty = new GetKnowledgebasePlainArgs();

    /**
     * The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of a Knowledge Base, as a URL path parameter.
     * 
     */
    @Import(name="knowledgeBaseId", required=true)
    private String knowledgeBaseId;

    /**
     * @return The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of a Knowledge Base, as a URL path parameter.
     * 
     */
    public String knowledgeBaseId() {
        return this.knowledgeBaseId;
    }

    private GetKnowledgebasePlainArgs() {}

    private GetKnowledgebasePlainArgs(GetKnowledgebasePlainArgs $) {
        this.knowledgeBaseId = $.knowledgeBaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetKnowledgebasePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetKnowledgebasePlainArgs $;

        public Builder() {
            $ = new GetKnowledgebasePlainArgs();
        }

        public Builder(GetKnowledgebasePlainArgs defaults) {
            $ = new GetKnowledgebasePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param knowledgeBaseId The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of a Knowledge Base, as a URL path parameter.
         * 
         * @return builder
         * 
         */
        public Builder knowledgeBaseId(String knowledgeBaseId) {
            $.knowledgeBaseId = knowledgeBaseId;
            return this;
        }

        public GetKnowledgebasePlainArgs build() {
            $.knowledgeBaseId = Objects.requireNonNull($.knowledgeBaseId, "expected parameter 'knowledgeBaseId' to be non-null");
            return $;
        }
    }

}
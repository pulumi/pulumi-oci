// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetNewsReportArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetNewsReportArgs Empty = new GetNewsReportArgs();

    /**
     * Unique news report identifier.
     * 
     */
    @Import(name="newsReportId", required=true)
    private Output<String> newsReportId;

    /**
     * @return Unique news report identifier.
     * 
     */
    public Output<String> newsReportId() {
        return this.newsReportId;
    }

    private GetNewsReportArgs() {}

    private GetNewsReportArgs(GetNewsReportArgs $) {
        this.newsReportId = $.newsReportId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetNewsReportArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetNewsReportArgs $;

        public Builder() {
            $ = new GetNewsReportArgs();
        }

        public Builder(GetNewsReportArgs defaults) {
            $ = new GetNewsReportArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param newsReportId Unique news report identifier.
         * 
         * @return builder
         * 
         */
        public Builder newsReportId(Output<String> newsReportId) {
            $.newsReportId = newsReportId;
            return this;
        }

        /**
         * @param newsReportId Unique news report identifier.
         * 
         * @return builder
         * 
         */
        public Builder newsReportId(String newsReportId) {
            return newsReportId(Output.of(newsReportId));
        }

        public GetNewsReportArgs build() {
            if ($.newsReportId == null) {
                throw new MissingRequiredPropertyException("GetNewsReportArgs", "newsReportId");
            }
            return $;
        }
    }

}

// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetRunStatementPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRunStatementPlainArgs Empty = new GetRunStatementPlainArgs();

    /**
     * The unique ID for the run
     * 
     */
    @Import(name="runId", required=true)
    private String runId;

    /**
     * @return The unique ID for the run
     * 
     */
    public String runId() {
        return this.runId;
    }

    /**
     * The unique ID for the statement.
     * 
     */
    @Import(name="statementId", required=true)
    private String statementId;

    /**
     * @return The unique ID for the statement.
     * 
     */
    public String statementId() {
        return this.statementId;
    }

    private GetRunStatementPlainArgs() {}

    private GetRunStatementPlainArgs(GetRunStatementPlainArgs $) {
        this.runId = $.runId;
        this.statementId = $.statementId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRunStatementPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRunStatementPlainArgs $;

        public Builder() {
            $ = new GetRunStatementPlainArgs();
        }

        public Builder(GetRunStatementPlainArgs defaults) {
            $ = new GetRunStatementPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param runId The unique ID for the run
         * 
         * @return builder
         * 
         */
        public Builder runId(String runId) {
            $.runId = runId;
            return this;
        }

        /**
         * @param statementId The unique ID for the statement.
         * 
         * @return builder
         * 
         */
        public Builder statementId(String statementId) {
            $.statementId = statementId;
            return this;
        }

        public GetRunStatementPlainArgs build() {
            $.runId = Objects.requireNonNull($.runId, "expected parameter 'runId' to be non-null");
            $.statementId = Objects.requireNonNull($.statementId, "expected parameter 'statementId' to be non-null");
            return $;
        }
    }

}
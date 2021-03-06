// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Nosql.inputs.TableTableLimitsArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TableArgs extends com.pulumi.resources.ResourceArgs {

    public static final TableArgs Empty = new TableArgs();

    /**
     * (Updatable) Compartment Identifier.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Complete CREATE TABLE DDL statement. When update ddl_statement, it should be ALTER TABLE DDL statement.
     * 
     */
    @Import(name="ddlStatement", required=true)
    private Output<String> ddlStatement;

    /**
     * @return (Updatable) Complete CREATE TABLE DDL statement. When update ddl_statement, it should be ALTER TABLE DDL statement.
     * 
     */
    public Output<String> ddlStatement() {
        return this.ddlStatement;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * True if table can be reclaimed after an idle period.
     * 
     */
    @Import(name="isAutoReclaimable")
    private @Nullable Output<Boolean> isAutoReclaimable;

    /**
     * @return True if table can be reclaimed after an idle period.
     * 
     */
    public Optional<Output<Boolean>> isAutoReclaimable() {
        return Optional.ofNullable(this.isAutoReclaimable);
    }

    /**
     * Table name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Table name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) Throughput and storage limits configuration of a table.
     * 
     */
    @Import(name="tableLimits", required=true)
    private Output<TableTableLimitsArgs> tableLimits;

    /**
     * @return (Updatable) Throughput and storage limits configuration of a table.
     * 
     */
    public Output<TableTableLimitsArgs> tableLimits() {
        return this.tableLimits;
    }

    private TableArgs() {}

    private TableArgs(TableArgs $) {
        this.compartmentId = $.compartmentId;
        this.ddlStatement = $.ddlStatement;
        this.definedTags = $.definedTags;
        this.freeformTags = $.freeformTags;
        this.isAutoReclaimable = $.isAutoReclaimable;
        this.name = $.name;
        this.tableLimits = $.tableLimits;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TableArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TableArgs $;

        public Builder() {
            $ = new TableArgs();
        }

        public Builder(TableArgs defaults) {
            $ = new TableArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param ddlStatement (Updatable) Complete CREATE TABLE DDL statement. When update ddl_statement, it should be ALTER TABLE DDL statement.
         * 
         * @return builder
         * 
         */
        public Builder ddlStatement(Output<String> ddlStatement) {
            $.ddlStatement = ddlStatement;
            return this;
        }

        /**
         * @param ddlStatement (Updatable) Complete CREATE TABLE DDL statement. When update ddl_statement, it should be ALTER TABLE DDL statement.
         * 
         * @return builder
         * 
         */
        public Builder ddlStatement(String ddlStatement) {
            return ddlStatement(Output.of(ddlStatement));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isAutoReclaimable True if table can be reclaimed after an idle period.
         * 
         * @return builder
         * 
         */
        public Builder isAutoReclaimable(@Nullable Output<Boolean> isAutoReclaimable) {
            $.isAutoReclaimable = isAutoReclaimable;
            return this;
        }

        /**
         * @param isAutoReclaimable True if table can be reclaimed after an idle period.
         * 
         * @return builder
         * 
         */
        public Builder isAutoReclaimable(Boolean isAutoReclaimable) {
            return isAutoReclaimable(Output.of(isAutoReclaimable));
        }

        /**
         * @param name Table name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Table name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param tableLimits (Updatable) Throughput and storage limits configuration of a table.
         * 
         * @return builder
         * 
         */
        public Builder tableLimits(Output<TableTableLimitsArgs> tableLimits) {
            $.tableLimits = tableLimits;
            return this;
        }

        /**
         * @param tableLimits (Updatable) Throughput and storage limits configuration of a table.
         * 
         * @return builder
         * 
         */
        public Builder tableLimits(TableTableLimitsArgs tableLimits) {
            return tableLimits(Output.of(tableLimits));
        }

        public TableArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.ddlStatement = Objects.requireNonNull($.ddlStatement, "expected parameter 'ddlStatement' to be non-null");
            $.tableLimits = Objects.requireNonNull($.tableLimits, "expected parameter 'tableLimits' to be non-null");
            return $;
        }
    }

}

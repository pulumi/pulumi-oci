// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Budget;

import com.pulumi.core.Output;
import com.pulumi.core.TypeShape;
import com.pulumi.deployment.Deployment;
import com.pulumi.deployment.InvokeOptions;
import com.pulumi.oci.Budget.inputs.GetAlertRuleArgs;
import com.pulumi.oci.Budget.inputs.GetAlertRulePlainArgs;
import com.pulumi.oci.Budget.inputs.GetAlertRulesArgs;
import com.pulumi.oci.Budget.inputs.GetAlertRulesPlainArgs;
import com.pulumi.oci.Budget.inputs.GetBudgetArgs;
import com.pulumi.oci.Budget.inputs.GetBudgetPlainArgs;
import com.pulumi.oci.Budget.inputs.GetBudgetsArgs;
import com.pulumi.oci.Budget.inputs.GetBudgetsPlainArgs;
import com.pulumi.oci.Budget.outputs.GetAlertRuleResult;
import com.pulumi.oci.Budget.outputs.GetAlertRulesResult;
import com.pulumi.oci.Budget.outputs.GetBudgetResult;
import com.pulumi.oci.Budget.outputs.GetBudgetsResult;
import com.pulumi.oci.Utilities;
import java.util.concurrent.CompletableFuture;

public final class BudgetFunctions {
    /**
     * This data source provides details about a specific Alert Rule resource in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets an Alert Rule for a specified budget.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetAlertRuleArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testAlertRule = BudgetFunctions.getAlertRule(GetAlertRuleArgs.builder()
     *             .alertRuleId(oci_budget_alert_rule.test_alert_rule().id())
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetAlertRuleResult> getAlertRule(GetAlertRuleArgs args) {
        return getAlertRule(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Alert Rule resource in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets an Alert Rule for a specified budget.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetAlertRuleArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testAlertRule = BudgetFunctions.getAlertRule(GetAlertRuleArgs.builder()
     *             .alertRuleId(oci_budget_alert_rule.test_alert_rule().id())
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetAlertRuleResult> getAlertRulePlain(GetAlertRulePlainArgs args) {
        return getAlertRulePlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Alert Rule resource in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets an Alert Rule for a specified budget.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetAlertRuleArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testAlertRule = BudgetFunctions.getAlertRule(GetAlertRuleArgs.builder()
     *             .alertRuleId(oci_budget_alert_rule.test_alert_rule().id())
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetAlertRuleResult> getAlertRule(GetAlertRuleArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:Budget/getAlertRule:getAlertRule", TypeShape.of(GetAlertRuleResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Alert Rule resource in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets an Alert Rule for a specified budget.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetAlertRuleArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testAlertRule = BudgetFunctions.getAlertRule(GetAlertRuleArgs.builder()
     *             .alertRuleId(oci_budget_alert_rule.test_alert_rule().id())
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetAlertRuleResult> getAlertRulePlain(GetAlertRulePlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:Budget/getAlertRule:getAlertRule", TypeShape.of(GetAlertRuleResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Alert Rules in Oracle Cloud Infrastructure Budget service.
     * 
     * Returns a list of Alert Rules for a specified budget.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetAlertRulesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testAlertRules = BudgetFunctions.getAlertRules(GetAlertRulesArgs.builder()
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .displayName(var_.alert_rule_display_name())
     *             .state(var_.alert_rule_state())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetAlertRulesResult> getAlertRules(GetAlertRulesArgs args) {
        return getAlertRules(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Alert Rules in Oracle Cloud Infrastructure Budget service.
     * 
     * Returns a list of Alert Rules for a specified budget.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetAlertRulesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testAlertRules = BudgetFunctions.getAlertRules(GetAlertRulesArgs.builder()
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .displayName(var_.alert_rule_display_name())
     *             .state(var_.alert_rule_state())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetAlertRulesResult> getAlertRulesPlain(GetAlertRulesPlainArgs args) {
        return getAlertRulesPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Alert Rules in Oracle Cloud Infrastructure Budget service.
     * 
     * Returns a list of Alert Rules for a specified budget.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetAlertRulesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testAlertRules = BudgetFunctions.getAlertRules(GetAlertRulesArgs.builder()
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .displayName(var_.alert_rule_display_name())
     *             .state(var_.alert_rule_state())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetAlertRulesResult> getAlertRules(GetAlertRulesArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:Budget/getAlertRules:getAlertRules", TypeShape.of(GetAlertRulesResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Alert Rules in Oracle Cloud Infrastructure Budget service.
     * 
     * Returns a list of Alert Rules for a specified budget.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetAlertRulesArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testAlertRules = BudgetFunctions.getAlertRules(GetAlertRulesArgs.builder()
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .displayName(var_.alert_rule_display_name())
     *             .state(var_.alert_rule_state())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetAlertRulesResult> getAlertRulesPlain(GetAlertRulesPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:Budget/getAlertRules:getAlertRules", TypeShape.of(GetAlertRulesResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Budget resource in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets a budget by the identifier.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetBudgetArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testBudget = BudgetFunctions.getBudget(GetBudgetArgs.builder()
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetBudgetResult> getBudget(GetBudgetArgs args) {
        return getBudget(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Budget resource in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets a budget by the identifier.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetBudgetArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testBudget = BudgetFunctions.getBudget(GetBudgetArgs.builder()
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetBudgetResult> getBudgetPlain(GetBudgetPlainArgs args) {
        return getBudgetPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides details about a specific Budget resource in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets a budget by the identifier.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetBudgetArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testBudget = BudgetFunctions.getBudget(GetBudgetArgs.builder()
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetBudgetResult> getBudget(GetBudgetArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:Budget/getBudget:getBudget", TypeShape.of(GetBudgetResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides details about a specific Budget resource in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets a budget by the identifier.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetBudgetArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testBudget = BudgetFunctions.getBudget(GetBudgetArgs.builder()
     *             .budgetId(oci_budget_budget.test_budget().id())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetBudgetResult> getBudgetPlain(GetBudgetPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:Budget/getBudget:getBudget", TypeShape.of(GetBudgetResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Budgets in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets a list of budgets in a compartment.
     * 
     * By default, ListBudgets returns budgets of the &#39;COMPARTMENT&#39; target type, and the budget records with only one target compartment OCID.
     * 
     * To list all budgets, set the targetType query parameter to ALL (for example: &#39;targetType=ALL&#39;).
     * 
     * Additional targetTypes would be available in future releases. Clients should ignore new targetTypes,
     * or upgrade to the latest version of the client SDK to handle new targetTypes.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetBudgetsArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testBudgets = BudgetFunctions.getBudgets(GetBudgetsArgs.builder()
     *             .compartmentId(var_.tenancy_ocid())
     *             .displayName(var_.budget_display_name())
     *             .state(var_.budget_state())
     *             .targetType(var_.budget_target_type())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetBudgetsResult> getBudgets(GetBudgetsArgs args) {
        return getBudgets(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Budgets in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets a list of budgets in a compartment.
     * 
     * By default, ListBudgets returns budgets of the &#39;COMPARTMENT&#39; target type, and the budget records with only one target compartment OCID.
     * 
     * To list all budgets, set the targetType query parameter to ALL (for example: &#39;targetType=ALL&#39;).
     * 
     * Additional targetTypes would be available in future releases. Clients should ignore new targetTypes,
     * or upgrade to the latest version of the client SDK to handle new targetTypes.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetBudgetsArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testBudgets = BudgetFunctions.getBudgets(GetBudgetsArgs.builder()
     *             .compartmentId(var_.tenancy_ocid())
     *             .displayName(var_.budget_display_name())
     *             .state(var_.budget_state())
     *             .targetType(var_.budget_target_type())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetBudgetsResult> getBudgetsPlain(GetBudgetsPlainArgs args) {
        return getBudgetsPlain(args, InvokeOptions.Empty);
    }
    /**
     * This data source provides the list of Budgets in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets a list of budgets in a compartment.
     * 
     * By default, ListBudgets returns budgets of the &#39;COMPARTMENT&#39; target type, and the budget records with only one target compartment OCID.
     * 
     * To list all budgets, set the targetType query parameter to ALL (for example: &#39;targetType=ALL&#39;).
     * 
     * Additional targetTypes would be available in future releases. Clients should ignore new targetTypes,
     * or upgrade to the latest version of the client SDK to handle new targetTypes.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetBudgetsArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testBudgets = BudgetFunctions.getBudgets(GetBudgetsArgs.builder()
     *             .compartmentId(var_.tenancy_ocid())
     *             .displayName(var_.budget_display_name())
     *             .state(var_.budget_state())
     *             .targetType(var_.budget_target_type())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static Output<GetBudgetsResult> getBudgets(GetBudgetsArgs args, InvokeOptions options) {
        return Deployment.getInstance().invoke("oci:Budget/getBudgets:getBudgets", TypeShape.of(GetBudgetsResult.class), args, Utilities.withVersion(options));
    }
    /**
     * This data source provides the list of Budgets in Oracle Cloud Infrastructure Budget service.
     * 
     * Gets a list of budgets in a compartment.
     * 
     * By default, ListBudgets returns budgets of the &#39;COMPARTMENT&#39; target type, and the budget records with only one target compartment OCID.
     * 
     * To list all budgets, set the targetType query parameter to ALL (for example: &#39;targetType=ALL&#39;).
     * 
     * Additional targetTypes would be available in future releases. Clients should ignore new targetTypes,
     * or upgrade to the latest version of the client SDK to handle new targetTypes.
     * 
     * ## Example Usage
     * ```java
     * package generated_program;
     * 
     * import com.pulumi.Context;
     * import com.pulumi.Pulumi;
     * import com.pulumi.core.Output;
     * import com.pulumi.oci.Budget.BudgetFunctions;
     * import com.pulumi.oci.Budget.inputs.GetBudgetsArgs;
     * import java.util.List;
     * import java.util.ArrayList;
     * import java.util.Map;
     * import java.io.File;
     * import java.nio.file.Files;
     * import java.nio.file.Paths;
     * 
     * public class App {
     *     public static void main(String[] args) {
     *         Pulumi.run(App::stack);
     *     }
     * 
     *     public static void stack(Context ctx) {
     *         final var testBudgets = BudgetFunctions.getBudgets(GetBudgetsArgs.builder()
     *             .compartmentId(var_.tenancy_ocid())
     *             .displayName(var_.budget_display_name())
     *             .state(var_.budget_state())
     *             .targetType(var_.budget_target_type())
     *             .build());
     * 
     *     }
     * }
     * ```
     * 
     */
    public static CompletableFuture<GetBudgetsResult> getBudgetsPlain(GetBudgetsPlainArgs args, InvokeOptions options) {
        return Deployment.getInstance().invokeAsync("oci:Budget/getBudgets:getBudgets", TypeShape.of(GetBudgetsResult.class), args, Utilities.withVersion(options));
    }
}
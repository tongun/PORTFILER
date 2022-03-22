'''
Provides functions for plotting ROC curves, Precision-Recall curves, anomaly scores per time wimdow, etc.
'''

# --- Imports ---
import os
import time
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
plt.switch_backend('agg')
from sklearn.metrics import auc
from constants_model import OUTPUT_DIR, FEATURE_COLS
from matplotlib import rcParams

# ---------------
class Plotting:
    """
    Class that defines the plotting
    """
    def __init__(self):
        self.linestyles = [
            ('solid', (0, ())),
            ('densely dashed', (0, (5, 1))),
            ('densely dashdotted', (0, (3, 1, 1, 1))),
            ('densely dashdotdotted', (0, (3, 1, 1, 1, 1, 1))),
            ('densely dotted', (0, (1, 1))),
            ('dashed', (0, (5, 5))),
            ('dotted', (0, (1, 1))),
            ('dashdotted', (0, (3, 5, 1, 5))),
            ('dashdotdotted', (0, (3, 5, 1, 5, 1, 5))),
                           ]
        self.style_index = 0

    def setup_plot(self, title, xlabel='False Positive Rate', ylabel='True Positive Rate', xlim=[-0.05, 1.05], ylim=[-0.05, 1.05], legend_loc='lower left'):
        '''
        Set up the ROC curve graph for plotting.
        :param info | str : The info (either port or wannacry variant) to put in the title.
        :param feature_cols | [str] : List of features used
        '''
        # plt.title(title, fontsize=13)
        if xlabel == "Recall" and "Recall" in ylabel:
            plt.legend(loc = legend_loc, bbox_to_anchor=(0, 0), fontsize=15, handlelength=4)
        else:
            plt.legend(loc = 'lower right', fontsize=15, handlelength=4)

        rcParams['pdf.fonttype'] = 42
        rcParams['ps.fonttype'] = 42
        plt.xlim(xlim)
        plt.ylim(ylim)
        plt.ylabel(ylabel, fontsize=20)
        plt.xlabel(xlabel, fontsize=20)
        ax = plt.gca()
        plt.setp(ax.get_xticklabels(),fontsize=12)
        plt.setp(ax.get_yticklabels(),fontsize=12)
        plt.tight_layout()
        self.style_index = 0

    def plot_roc(self, fpr, tpr, port=None, wc_var=None, feature=None):
        '''
        Plots the ROC curve for the given fpr and tpr lists. Saves these too a file.
        :param fpr | [float] : The list of fpr
        :param tpr | [float] : The list of tpr
        :param port | int : The port on which we are testing
        :param wc_var | str : The wannacry variant on which we are testing
        '''
        if port: print("\nPort:", port)
        print("Fpr:", fpr)
        print("Tpr:", tpr)
        print("auc(fpr, tpr):", auc(fpr, tpr))
        info = ""
        if feature: info += feature
        if port: info += "Port: {}".format(port)
        if wc_var: info += wc_var
        plt.plot(fpr, tpr, linewidth=3, label = "{}, AUC: {}".format(info, round(auc(fpr, tpr), 2)), linestyle=self.linestyles[self.style_index][1])
        self.style_index += 1



    def plot_prec_recall(self, recall, prec, port=None, wc_var=None, feature=None):
        '''
        Plots the PR curve for the given precision and recall lists.
        :param recall | [float] : The list of recall values
        :param prec | [float] : The list of precision values
        :param port | int : The port on which we are testing
        :param wc_var | str : The wannacry variant on which we are testing
        '''
        if port: print("\nPort:", port)
        print("Prec:", prec)
        print("Recall:", recall)
        info = ""
        if feature: info += feature
        if port: info += "Port: {}".format(port)
        if wc_var: info += wc_var
        plt.plot(recall, prec, linewidth=3, label = "{}, AUC: {}".format(info, round(auc(recall, prec), 2)), linestyle = self.linestyles[self.style_index][1])
        self.style_index += 1


    def plot_auc(self, xvals, auc_scores, port=None, wc_var=None):
        '''
        Plots the AUC curve for the given auc scores.
        :param xvals | [float] : The list of x-values, such as propagation rates
        :param auc | [float] : The list of AUCs
        :param port | int : The port on which we are testing
        :param wc_var | str : The wannacry variant on which we are testing
        '''
        if port: print("\nPort:", port)
        print("x-vals:", xvals)
        print("aucs:", auc_scores)
        info = ""
        if port: info += "Port: {}".format(port)
        if wc_var: info += wc_var
        plt.plot(xvals, auc_scores, linewidth=3, label = "{}".format(info), linestyle = self.linestyles[self.style_index][1])
        self.style_index += 1

    def plot_scores_for_windows(self, scores, windows=None, port=None, wc_var=None, output_dir=OUTPUT_DIR):
        info = ""
        wc_str = ""
        if port:
            info += "Port: {} ".format(port)
        if wc_var:
            info += wc_var
            wc_str = wc_var
        if not windows:
            windows = range(0, 1440) # 1 day
        print("\nPlotting kde")
        print("Info: ", info)
        print("Windows: ", list(windows))
        plt.plot(windows, scores, linewidth=3, label = "{}".format(info))
        [title, output_file] = self.get_plot_title_and_file('Scores', 'scores', port, wc_str, output_dir)
        self.setup_plot(title, xlabel='Windows', ylabel='Scores', xlim=[min(windows), max(windows)], ylim=[min(scores), max(scores)])
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        self.save_and_clear_plot(output_file)
        print("Finished printing .png", output_file)

    def get_plot_title_and_file(self, name_title, name_file, port='', wc_str='', output_dir=OUTPUT_DIR):
        info = ""
        if port:
            info += "p{}_".format(port)
        if wc_str:
            info += wc_str

        if len(FEATURE_COLS) > 4:
            title = "{} {}\n{} features".format(name_title, info, len(FEATURE_COLS))
            out_file = os.path.join(output_dir, name_file, wc_str, "{}_{}_{}_ts{}.png".format(name_file, info, len(FEATURE_COLS), int(time.time())))
        else:
            title = "{} {}\n{}".format(name_title, info, "_".join(FEATURE_COLS))
            out_file = os.path.join(output_dir, name_file, wc_str, "{}_{}_{}_ts{}.png".format(name_file, info, '_'.join(FEATURE_COLS), int(time.time())))
        return [title, out_file]

    def plot_metrics(self, metrics_data, attack_windows_num, model, limit_points):
        '''
        '''

        print("metrics data:")
        print(metrics_data)
        k = metrics_data['k']
        tp_by_k = metrics_data['tp_total'] / attack_windows_num
        fp_by_k = (k - metrics_data['tp_total']) / k

        print("tp_by_k:", tp_by_k, metrics_data['tp_total'], attack_windows_num)
        print("fp_by_k:", fp_by_k)

        plt.plot(k[:limit_points], tp_by_k[:limit_points], linewidth=3, label="{}".format(model), linestyle = self.linestyles[self.style_index][1])
        self.style_index += 1

    def save_and_clear_plot(self, output_file, is_pdf = False):
        '''
        Saves the roc plot to the given output file, clears the plot.
        :param output_file | str : The location to save the plot.
        '''
        output_file_pdf = output_file[:-3] + 'pdf'
        plt.savefig(output_file)
        plt.savefig(output_file_pdf)
        plt.clf()

# ------------

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Image
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import os
import tempfile
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report

# Function to parse log file
def parse_log_file(file_name):
    data = []
    with open(file_name, 'r') as f:
        for line in f:
            parts = line.strip().split(' ', 3)
            timestamp = parts[0] + " " + parts[1]
            log_level = parts[2]
            activity = parts[3]
            data.append([timestamp, log_level, activity])
    return pd.DataFrame(data, columns=['timestamp', 'log_level', 'activity'])

# Function to preprocess the log data
def preprocess_logs(log_file):
    logs = parse_log_file(log_file)
    logs['failed_logins'] = logs['activity'].apply(lambda x: 1 if 'failed login' in x else 0)
    logs['unauthorized_access'] = logs['activity'].apply(lambda x: 1 if 'Unauthorized access' in x else 0)
    logs['malware_detected'] = logs['activity'].apply(lambda x: 1 if 'Malware detected' in x else 0)
    X = logs[['failed_logins', 'unauthorized_access', 'malware_detected']]
    y = (logs['failed_logins'] + logs['unauthorized_access'] + logs['malware_detected']).apply(lambda x: 1 if x > 0 else 0)
    return X, y

def train_and_evaluate(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    model = DecisionTreeClassifier()
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    intrusion_detected = y.sum() > 0
    return accuracy, report, intrusion_detected

# Function to create PDF report in table format
def create_pdf_report(accuracy, report, file_path, plot_path):
    pdf_file = file_path.replace('.log', '_report.pdf')
    doc = SimpleDocTemplate(pdf_file, pagesize=letter)
    elements = []

    # Title
    styles = getSampleStyleSheet()
    title = "Intrusion Detection Report"
    title_para = Paragraph(title, styles["Title"])
    elements.append(title_para)

    # Classification report in table format
    data = [['Class', 'Precision', 'Recall', 'F1-Score', 'Support']]
    for key, value in report.items():
        if isinstance(value, dict):
            data.append([key, f"{value['precision']:.2f}", f"{value['recall']:.2f}", f"{value['f1-score']:.2f}", f"{value['support']}"])

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)

    # Insert the graph into the PDF
    img = Image(plot_path, width=400, height=300)
    elements.append(Paragraph("    \n       "))
    elements.append(img)

    doc.build(elements)
    messagebox.showinfo("PDF Report", f"PDF report generated: {pdf_file}")

# Function to display analysis report in table format
def display_analysis_report(accuracy, report, intrusion_detected):
    report_text = f"Accuracy: {accuracy:.2f}\n\nClassification Report:\n\n"
    report_text += f"{'Class':<15} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'Support':<10}\n"
    for key, value in report.items():
        if isinstance(value, dict):
            report_text += f"{key:<15} {value['precision']:<10.2f} {value['recall']:<10.2f} {value['f1-score']:<10.2f} {value['support']:<10}\n"
    
    if intrusion_detected:
        messagebox.showwarning("Intrusion Detected", "Intrusion detected in the log file!")
    else:
        messagebox.showinfo("No Intrusion Detected", "No intrusion detected in the log file.")
    messagebox.showinfo("Analysis Report", report_text)

# Function to plot the graph
def plot_graph(frame, report):
    for widget in frame.winfo_children():
        widget.destroy()
    
    fig = Figure(figsize=(5, 4), dpi=100)
    ax = fig.add_subplot(111)
    classes = list(report.keys())[:-3]  # Exclude 'accuracy', 'macro avg', and 'weighted avg'
    f1_scores = [report[cls]['f1-score'] for cls in classes]
    ax.bar(classes, f1_scores, color='cyan')
    ax.set_xlabel('Classes')
    ax.set_ylabel('F1 Score')
    ax.set_title('F1 Score by Class')

    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # Save the plot to a temporary file
    tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
    plot_path = tmpfile.name
    fig.savefig(plot_path)
    plt.close(fig)

    return plot_path

# Function to show the graph in a new dialog box
def show_graph_dialog(report):
    dialog = tk.Toplevel(root)
    dialog.title("F1 Score by Class")
    dialog.geometry("500x400")
    
    fig = Figure(figsize=(5, 4), dpi=100)
    ax = fig.add_subplot(111)
    classes = list(report.keys())[:-3]  # Exclude 'accuracy', 'macro avg', and 'weighted avg'
    f1_scores = [report[cls]['f1-score'] for cls in classes]
    ax.bar(classes, f1_scores, color='cyan')
    ax.set_xlabel('Classes')
    ax.set_ylabel('F1 Score')
    ax.set_title('F1 Score by Class')
    
    canvas = FigureCanvasTkAgg(fig, master=dialog)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

# Function to run analysis
def run_analysis(file_path, report_frame, graph_frame, loading_label):
    loading_label.pack(pady=20)
    X, y = preprocess_logs(file_path)
    accuracy, report, intrusion_detected = train_and_evaluate(X, y)
    display_analysis_report(accuracy, report, intrusion_detected)
    plot_path = plot_graph(graph_frame, report)
    loading_label.pack_forget()
    show_graph_dialog(report)  # Show the graph in a dialog box
    return accuracy, report, plot_path

# Function to select log file and detect intrusions
def select_log_file(report_frame, graph_frame, loading_label, pdf_button):
    file_path = filedialog.askopenfilename(filetypes=[("Log files", "*.log")])
    if file_path:
        analysis_thread = threading.Thread(target=run_analysis, args=(file_path, report_frame, graph_frame, loading_label))
        analysis_thread.start()
        # Define a lambda function to capture plot_path
        pdf_button.config(command=lambda: generate_pdf(file_path, report_frame, graph_frame, loading_label))

# Function to generate PDF report
def generate_pdf(file_path, report_frame, graph_frame, loading_label):
    accuracy, report, plot_path = run_analysis(file_path, report_frame, graph_frame, loading_label)
    create_pdf_report(accuracy, report, file_path, plot_path)

# Function to switch frames
def show_frame(frame):
    frame.tkraise()

# Create the main application window
root = tk.Tk()
root.title("Intrusion Detection System")
root.geometry("1000x800")
root.configure(bg='black')

# Create frames
home_frame = tk.Frame(root, bg='black')
analysis_frame = tk.Frame(root, bg='black')

for frame in (home_frame, analysis_frame):
    frame.grid(row=1, column=0, sticky='nsew')

# Header
header = tk.Frame(root, bg='black')
header.grid(row=0, column=0, sticky='ew')
header_label = tk.Label(header, text="Intrusion Detection System", font=("Helvetica", 24, "italic"), fg="cyan", bg="black", anchor="w")
header_label.grid(row=0, column=0, padx=10, pady=10)
home_nav = tk.Label(header, text="Home", font=("Helvetica", 18, "italic"), fg="white", bg="black", cursor="hand2")
home_nav.grid(row=0, column=1, padx=10, pady=10)
home_nav.bind("<Button-1>", lambda e: show_frame(home_frame))
analysis_nav = tk.Label(header, text="Analysis", font=("Helvetica", 18, "italic"), fg="white", bg="black", cursor="hand2")
analysis_nav.grid(row=0, column=2, padx=10, pady=10)
analysis_nav.bind("<Button-1>", lambda e: show_frame(analysis_frame))

# Home frame
home_label = tk.Label(home_frame, text="Welcome to Intrusion Detection System", font=("Helvetica", 24), fg="cyan", bg="black")
home_label.pack(pady=40, padx=450)
description_label = tk.Label(home_frame, text="This system analyzes log files to detect potential intrusions using machine learning. The algorithm employed is a Decision Tree Classifier. The steps involved in the process include parsing the log file to extract timestamps, log levels, and activities; preprocessing the log data to extract features such as failed logins, unauthorized access attempts, and malware detection; training the classifier using the preprocessed data; evaluating the classifier's performance using accuracy and classification metrics; and generating a visual representation of the classifier's performance. The results of the analysis can be viewed in the Analysis section, where you can also generate a PDF report of the findings.",
                             font=("Helvetica", 14), fg="white", bg="black", justify="left", wraplength=700)
description_label.pack(pady=40, padx=40)
image = tk.PhotoImage(file="img.png")
image_label = tk.Label(home_frame, image=image, bg='black')
image_label.image = image  # Keep a reference to avoid garbage collection
image_label.pack( padx=20, pady=20)

# Centering the text in home frame
home_label.pack_configure(anchor="center")
description_label.pack_configure(anchor="center")

# Analysis frame
steps_description = tk.Label(analysis_frame, text="Steps involved in the process:\n1. Parse the log file to extract timestamps, log levels, and activities.\n2. Preprocess the log data to extract features such as failed logins, unauthorized access attempts, and malware detection.\n3. Train a Decision Tree Classifier using the preprocessed data.\n4. Evaluate the classifier's performance using accuracy and classification metrics.\n5. Generate a visual representation of the classifier's performance.\n6. Display the results and provide an option to generate a PDF report.",
                             font=("Helvetica", 14), fg="white", bg="black", justify="left", wraplength=700)
steps_description.pack(pady=20)

# Frames for analysis report and graph
report_frame = tk.Frame(analysis_frame, bg='black')
report_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

graph_frame = tk.Frame(analysis_frame, bg='black')
graph_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Loading label
loading_label = tk.Label(analysis_frame, text="Loading...", font=("Helvetica", 14), fg="white", bg="black")

# Select log file button
select_button = tk.Button(analysis_frame, text="Select Log File", font=("Helvetica", 14), command=lambda: select_log_file(report_frame, graph_frame, loading_label, print_button))
select_button.pack(pady=20)

# Print report button
print_button = tk.Button(analysis_frame, text="Print Report", font=("Helvetica", 14))
print_button.pack(pady=20)

# Explanation of Decision Tree Algorithm
algorithm_description = tk.Label(analysis_frame, text="Decision Tree Algorithm:\nA Decision Tree is a supervised learning algorithm that is mostly used for classification problems. It works for both categorical and continuous input and output variables. In this algorithm, we start at the root of the tree, compare the values of the root attribute with the record’s attribute, and follow the branch corresponding to that value and jump to the next node.\n\nAnalysis Report Outcomes:\nThe analysis report generated provides the accuracy of the classification and a detailed classification report that includes precision, recall, and F1-score for each class. These metrics help in understanding the performance of the classifier.",
                                   font=("Helvetica", 14), fg="white", bg="black", justify="left", wraplength=700)
algorithm_description.pack(pady=10,padx=10)

# Show home frame initially
show_frame(home_frame)

# Run the application
root.mainloop()
